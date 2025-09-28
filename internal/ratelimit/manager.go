package ratelimit

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

// Manager handles rate limiting at multiple levels
type Manager struct {
	redis         *redis.Client
	logger        *logrus.Logger
	config        Config
	
	// In-memory rate limiters
	tenantLimiters map[string]*rate.Limiter
	targetLimiters map[string]*rate.Limiter
	asnLimiters    map[string]*rate.Limiter
	globalLimiter  *rate.Limiter
	mutex          sync.RWMutex
	
	// ASN cache
	asnCache       *cache.Cache
	
	// RPKI validators
	rpkiValidators []RPKIValidator
	
	// Metrics
	metrics        *Metrics
}

// Config holds rate limiting configuration
type Config struct {
	// Rate limits (requests per second)
	GlobalLimit        int
	PerTenantLimit     int
	PerTargetLimit     int
	PerASNLimit        int
	
	// Burst sizes
	GlobalBurst        int
	PerTenantBurst     int
	PerTargetBurst     int
	PerASNBurst        int
	
	// ASN grouping
	ASNGrouping        bool
	ASNLookupTimeout   time.Duration
	
	// RPKI validation
	RPKIEnabled        bool
	RPKIValidators     []string
	
	// Backpressure
	BackpressureEnabled bool
	BackpressureThreshold float64
	
	// Scope enforcement
	ScopeEnforcement   bool
	OptOutList         []string
}

// Metrics tracks rate limiting metrics
type Metrics struct {
	RequestsAllowed   uint64
	RequestsThrottled uint64
	RequestsBlocked   uint64
	ASNLookups        uint64
	RPKIValidations   uint64
	mutex             sync.RWMutex
}

// ASNInfo contains ASN information
type ASNInfo struct {
	ASN         uint32    `json:"asn"`
	Name        string    `json:"name"`
	Country     string    `json:"country"`
	Prefixes    []string  `json:"prefixes"`
	LastUpdated time.Time `json:"last_updated"`
}

// RPKIValidator interface for RPKI validation
type RPKIValidator interface {
	Validate(ctx context.Context, prefix string, asn uint32) (RPKIStatus, error)
}

// RPKIStatus represents RPKI validation status
type RPKIStatus string

const (
	RPKIValid       RPKIStatus = "valid"
	RPKIInvalid     RPKIStatus = "invalid"
	RPKINotFound    RPKIStatus = "notfound"
	RPKIUnknown     RPKIStatus = "unknown"
)

// RateLimitDecision represents the rate limiting decision
type RateLimitDecision struct {
	Allowed       bool
	WaitDuration  time.Duration
	Reason        string
	LimitType     string
	CurrentRate   float64
	LimitRate     float64
}

// New creates a new rate limit manager
func New(config Config, redisClient *redis.Client, logger *logrus.Logger) (*Manager, error) {
	manager := &Manager{
		redis:          redisClient,
		logger:         logger,
		config:         config,
		tenantLimiters: make(map[string]*rate.Limiter),
		targetLimiters: make(map[string]*rate.Limiter),
		asnLimiters:    make(map[string]*rate.Limiter),
		asnCache:       cache.New(1*time.Hour, 10*time.Minute),
		metrics:        &Metrics{},
	}
	
	// Initialize global limiter
	manager.globalLimiter = rate.NewLimiter(
		rate.Limit(config.GlobalLimit),
		config.GlobalBurst,
	)
	
	// Initialize RPKI validators
	if config.RPKIEnabled {
		for _, validatorURL := range config.RPKIValidators {
			validator := &HTTPRPKIValidator{
				BaseURL:    validatorURL,
				HTTPClient: &http.Client{Timeout: 5 * time.Second},
			}
			manager.rpkiValidators = append(manager.rpkiValidators, validator)
		}
	}
	
	// Start cleanup routine
	go manager.cleanupRoutine()
	
	return manager, nil
}

// CheckLimit checks if a request should be rate limited
func (m *Manager) CheckLimit(ctx context.Context, tenantID, targetType, target string) (*RateLimitDecision, error) {
	// 1. Check global rate limit
	if !m.globalLimiter.Allow() {
		m.incrementThrottled()
		return &RateLimitDecision{
			Allowed:      false,
			WaitDuration: m.getWaitTime(m.globalLimiter),
			Reason:       "Global rate limit exceeded",
			LimitType:    "global",
			CurrentRate:  float64(m.globalLimiter.Limit()),
			LimitRate:    float64(m.config.GlobalLimit),
		}, nil
	}
	
	// 2. Check tenant rate limit
	tenantLimiter := m.getTenantLimiter(tenantID)
	if !tenantLimiter.Allow() {
		m.incrementThrottled()
		return &RateLimitDecision{
			Allowed:      false,
			WaitDuration: m.getWaitTime(tenantLimiter),
			Reason:       "Tenant rate limit exceeded",
			LimitType:    "tenant",
			CurrentRate:  float64(tenantLimiter.Limit()),
			LimitRate:    float64(m.config.PerTenantLimit),
		}, nil
	}
	
	// 3. Check if target is in opt-out list
	if m.isOptedOut(target) {
		m.incrementBlocked()
		return &RateLimitDecision{
			Allowed:   false,
			Reason:    "Target has opted out of scanning",
			LimitType: "opt-out",
		}, nil
	}
	
	// 4. Check scope enforcement
	if m.config.ScopeEnforcement {
		inScope, err := m.checkScope(ctx, tenantID, targetType, target)
		if err != nil {
			return nil, fmt.Errorf("scope check failed: %w", err)
		}
		if !inScope {
			m.incrementBlocked()
			return &RateLimitDecision{
				Allowed:   false,
				Reason:    "Target is outside authorized scope",
				LimitType: "scope",
			}, nil
		}
	}
	
	// 5. Check target rate limit
	targetLimiter := m.getTargetLimiter(target)
	if !targetLimiter.Allow() {
		m.incrementThrottled()
		return &RateLimitDecision{
			Allowed:      false,
			WaitDuration: m.getWaitTime(targetLimiter),
			Reason:       "Target rate limit exceeded",
			LimitType:    "target",
			CurrentRate:  float64(targetLimiter.Limit()),
			LimitRate:    float64(m.config.PerTargetLimit),
		}, nil
	}
	
	// 6. Check ASN rate limit if applicable
	if m.config.ASNGrouping && (targetType == "ip" || targetType == "cidr") {
		asn, err := m.getASN(ctx, target)
		if err != nil {
			m.logger.WithError(err).Warn("Failed to get ASN for target")
		} else if asn != 0 {
			// Check ASN rate limit
			asnLimiter := m.getASNLimiter(asn)
			if !asnLimiter.Allow() {
				m.incrementThrottled()
				return &RateLimitDecision{
					Allowed:      false,
					WaitDuration: m.getWaitTime(asnLimiter),
					Reason:       fmt.Sprintf("ASN %d rate limit exceeded", asn),
					LimitType:    "asn",
					CurrentRate:  float64(asnLimiter.Limit()),
					LimitRate:    float64(m.config.PerASNLimit),
				}, nil
			}
			
			// 7. Check RPKI validation if enabled
			if m.config.RPKIEnabled {
				rpkiStatus, err := m.validateRPKI(ctx, target, asn)
				if err != nil {
					m.logger.WithError(err).Warn("RPKI validation failed")
				} else if rpkiStatus == RPKIInvalid {
					m.incrementBlocked()
					return &RateLimitDecision{
						Allowed:   false,
						Reason:    "RPKI validation failed - invalid route origin",
						LimitType: "rpki",
					}, nil
				}
			}
		}
	}
	
	// 8. Check backpressure if enabled
	if m.config.BackpressureEnabled {
		if m.shouldApplyBackpressure() {
			m.incrementThrottled()
			return &RateLimitDecision{
				Allowed:      false,
				WaitDuration: 5 * time.Second,
				Reason:       "System under high load - backpressure applied",
				LimitType:    "backpressure",
			}, nil
		}
	}
	
	m.incrementAllowed()
	return &RateLimitDecision{
		Allowed: true,
		Reason:  "Request allowed",
	}, nil
}

// getTenantLimiter gets or creates a rate limiter for a tenant
func (m *Manager) getTenantLimiter(tenantID string) *rate.Limiter {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	limiter, exists := m.tenantLimiters[tenantID]
	if !exists {
		limiter = rate.NewLimiter(
			rate.Limit(m.config.PerTenantLimit),
			m.config.PerTenantBurst,
		)
		m.tenantLimiters[tenantID] = limiter
	}
	
	return limiter
}

// getTargetLimiter gets or creates a rate limiter for a target
func (m *Manager) getTargetLimiter(target string) *rate.Limiter {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	limiter, exists := m.targetLimiters[target]
	if !exists {
		limiter = rate.NewLimiter(
			rate.Limit(m.config.PerTargetLimit),
			m.config.PerTargetBurst,
		)
		m.targetLimiters[target] = limiter
	}
	
	return limiter
}

// getASNLimiter gets or creates a rate limiter for an ASN
func (m *Manager) getASNLimiter(asn uint32) *rate.Limiter {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	asnKey := fmt.Sprintf("AS%d", asn)
	limiter, exists := m.asnLimiters[asnKey]
	if !exists {
		limiter = rate.NewLimiter(
			rate.Limit(m.config.PerASNLimit),
			m.config.PerASNBurst,
		)
		m.asnLimiters[asnKey] = limiter
	}
	
	return limiter
}

// getASN looks up the ASN for an IP address
func (m *Manager) getASN(ctx context.Context, target string) (uint32, error) {
	// Check cache first
	if cached, found := m.asnCache.Get(target); found {
		return cached.(uint32), nil
	}
	
	m.incrementASNLookups()
	
	// Parse IP
	ip := net.ParseIP(target)
	if ip == nil {
		// Try parsing as CIDR
		ipNet, err := net.ParseCIDR(target)
		if err != nil {
			return 0, fmt.Errorf("invalid IP or CIDR: %s", target)
		}
		ip = ipNet.IP
	}
	
	// Use Team Cymru IP to ASN mapping service
	ctx, cancel := context.WithTimeout(ctx, m.config.ASNLookupTimeout)
	defer cancel()
	
	// Query using DNS (simplified version)
	// In production, use BGP looking glass or commercial API
	asn, err := m.queryASNViaDNS(ctx, ip)
	if err != nil {
		return 0, err
	}
	
	// Cache the result
	m.asnCache.Set(target, asn, cache.DefaultExpiration)
	
	return asn, nil
}

// queryASNViaDNS queries ASN via DNS (Team Cymru service)
func (m *Manager) queryASNViaDNS(ctx context.Context, ip net.IP) (uint32, error) {
	// This is a simplified implementation
	// In production, implement proper DNS lookup to origin.asn.cymru.com
	// Format: <reversed-ip>.origin.asn.cymru.com
	
	// For now, return a mock ASN
	// In production, implement actual DNS lookup
	return 64512, nil
}

// validateRPKI validates the route origin using RPKI
func (m *Manager) validateRPKI(ctx context.Context, prefix string, asn uint32) (RPKIStatus, error) {
	m.incrementRPKIValidations()
	
	// Try each validator
	for _, validator := range m.rpkiValidators {
		status, err := validator.Validate(ctx, prefix, asn)
		if err != nil {
			m.logger.WithError(err).Warn("RPKI validator error")
			continue
		}
		
		// If any validator returns invalid, reject
		if status == RPKIInvalid {
			return RPKIInvalid, nil
		}
		
		// If valid, accept
		if status == RPKIValid {
			return RPKIValid, nil
		}
	}
	
	// Default to unknown if no definitive answer
	return RPKIUnknown, nil
}

// checkScope checks if the target is within authorized scope
func (m *Manager) checkScope(ctx context.Context, tenantID, targetType, target string) (bool, error) {
	// Query Redis for tenant scope
	key := fmt.Sprintf("scope:%s:%s", tenantID, targetType)
	
	result, err := m.redis.SIsMember(ctx, key, target).Result()
	if err != nil {
		if err == redis.Nil {
			// No scope defined, default to deny
			return false, nil
		}
		return false, err
	}
	
	return result, nil
}

// isOptedOut checks if a target is in the opt-out list
func (m *Manager) isOptedOut(target string) bool {
	for _, optOut := range m.config.OptOutList {
		if optOut == target {
			return true
		}
		
		// Check if target is within opt-out CIDR
		_, optOutNet, err := net.ParseCIDR(optOut)
		if err == nil {
			targetIP := net.ParseIP(target)
			if targetIP != nil && optOutNet.Contains(targetIP) {
				return true
			}
		}
	}
	
	return false
}

// shouldApplyBackpressure checks if backpressure should be applied
func (m *Manager) shouldApplyBackpressure() bool {
	// Check Redis for system load metrics
	ctx := context.Background()
	
	// Get current queue depth
	queueDepth, err := m.redis.LLen(ctx, "scan_queue").Result()
	if err != nil {
		m.logger.WithError(err).Warn("Failed to get queue depth")
		return false
	}
	
	// Get worker utilization
	workerUtil, err := m.redis.Get(ctx, "worker_utilization").Float64()
	if err != nil && err != redis.Nil {
		m.logger.WithError(err).Warn("Failed to get worker utilization")
		return false
	}
	
	// Apply backpressure if queue is too deep or workers are overloaded
	return queueDepth > 10000 || workerUtil > m.config.BackpressureThreshold
}

// getWaitTime calculates how long to wait before retry
func (m *Manager) getWaitTime(limiter *rate.Limiter) time.Duration {
	reservation := limiter.Reserve()
	waitTime := reservation.Delay()
	reservation.Cancel()
	return waitTime
}

// cleanupRoutine periodically cleans up unused limiters
func (m *Manager) cleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		m.mutex.Lock()
		
		// Clean up limiters that haven't been used recently
		// In production, track last usage time
		
		// For now, clear if too many limiters
		if len(m.tenantLimiters) > 1000 {
			m.tenantLimiters = make(map[string]*rate.Limiter)
		}
		if len(m.targetLimiters) > 10000 {
			m.targetLimiters = make(map[string]*rate.Limiter)
		}
		if len(m.asnLimiters) > 1000 {
			m.asnLimiters = make(map[string]*rate.Limiter)
		}
		
		m.mutex.Unlock()
	}
}

// GetMetrics returns current metrics
func (m *Manager) GetMetrics() Metrics {
	m.metrics.mutex.RLock()
	defer m.metrics.mutex.RUnlock()
	
	return *m.metrics
}

// Metric increment helpers
func (m *Manager) incrementAllowed() {
	m.metrics.mutex.Lock()
	m.metrics.RequestsAllowed++
	m.metrics.mutex.Unlock()
}

func (m *Manager) incrementThrottled() {
	m.metrics.mutex.Lock()
	m.metrics.RequestsThrottled++
	m.metrics.mutex.Unlock()
}

func (m *Manager) incrementBlocked() {
	m.metrics.mutex.Lock()
	m.metrics.RequestsBlocked++
	m.metrics.mutex.Unlock()
}

func (m *Manager) incrementASNLookups() {
	m.metrics.mutex.Lock()
	m.metrics.ASNLookups++
	m.metrics.mutex.Unlock()
}

func (m *Manager) incrementRPKIValidations() {
	m.metrics.mutex.Lock()
	m.metrics.RPKIValidations++
	m.metrics.mutex.Unlock()
}

// HTTPRPKIValidator implements RPKI validation via HTTP API
type HTTPRPKIValidator struct {
	BaseURL    string
	HTTPClient *http.Client
}

// Validate performs RPKI validation
func (v *HTTPRPKIValidator) Validate(ctx context.Context, prefix string, asn uint32) (RPKIStatus, error) {
	url := fmt.Sprintf("%s/validate?prefix=%s&asn=%d", v.BaseURL, prefix, asn)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return RPKIUnknown, err
	}
	
	resp, err := v.HTTPClient.Do(req)
	if err != nil {
		return RPKIUnknown, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return RPKIUnknown, fmt.Errorf("RPKI validator returned status %d", resp.StatusCode)
	}
	
	var result struct {
		Status string `json:"status"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return RPKIUnknown, err
	}
	
	return RPKIStatus(result.Status), nil
}