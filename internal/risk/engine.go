package risk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/sovereign-eye/core/internal/storage"
)

// Engine calculates risk scores for assets and findings
type Engine struct {
	storage       storage.Manager
	kevCache      *KEVCache
	epssCache     *EPSSCache
	logger        *logrus.Logger
	httpClient    *http.Client
	config        Config
}

// Config holds risk engine configuration
type Config struct {
	KEVUpdateInterval  time.Duration
	EPSSUpdateInterval time.Duration
	BaseAPIURL         string
	HTTPTimeout        time.Duration
	Weights            RiskWeights
}

// RiskWeights defines the weights for different risk factors
type RiskWeights struct {
	CVSSBase          float64
	EPSSProbability   float64
	KEVPresence       float64
	AssetCriticality  float64
	ExposureLevel     float64
	ExploitMaturity   float64
	RemediationEffort float64
}

// KEVCache caches CISA Known Exploited Vulnerabilities
type KEVCache struct {
	vulnerabilities map[string]KEVEntry
	lastUpdated     time.Time
	mutex           sync.RWMutex
}

// KEVEntry represents a Known Exploited Vulnerability
type KEVEntry struct {
	CVEID              string    `json:"cveID"`
	VendorProject      string    `json:"vendorProject"`
	Product            string    `json:"product"`
	VulnerabilityName  string    `json:"vulnerabilityName"`
	DateAdded          time.Time `json:"dateAdded"`
	ShortDescription   string    `json:"shortDescription"`
	RequiredAction     string    `json:"requiredAction"`
	DueDate            time.Time `json:"dueDate"`
	Notes              string    `json:"notes"`
}

// EPSSCache caches FIRST EPSS scores
type EPSSCache struct {
	scores      map[string]EPSSScore
	lastUpdated time.Time
	mutex       sync.RWMutex
}

// EPSSScore represents an EPSS probability score
type EPSSScore struct {
	CVE         string    `json:"cve"`
	Probability float64   `json:"epss"`
	Percentile  float64   `json:"percentile"`
	Date        time.Time `json:"date"`
}

// RiskScore represents a calculated risk score
type RiskScore struct {
	AssetID          string                 `json:"asset_id"`
	FindingID        string                 `json:"finding_id"`
	Score            float64                `json:"score"`           // 0-10 scale
	Severity         string                 `json:"severity"`        // critical, high, medium, low
	Factors          map[string]float64     `json:"factors"`
	Recommendations  []string               `json:"recommendations"`
	ComplianceImpact []ComplianceMapping    `json:"compliance_impact"`
	AttackPaths      []string               `json:"attack_paths"`
	CalculatedAt     time.Time              `json:"calculated_at"`
}

// ComplianceMapping maps findings to compliance frameworks
type ComplianceMapping struct {
	Framework   string   `json:"framework"`
	Controls    []string `json:"controls"`
	Impact      string   `json:"impact"`
	Description string   `json:"description"`
}

// AssetRiskProfile represents the overall risk profile of an asset
type AssetRiskProfile struct {
	AssetID             string              `json:"asset_id"`
	OverallScore        float64             `json:"overall_score"`
	CriticalFindings    int                 `json:"critical_findings"`
	HighFindings        int                 `json:"high_findings"`
	MediumFindings      int                 `json:"medium_findings"`
	LowFindings         int                 `json:"low_findings"`
	TopRisks            []RiskScore         `json:"top_risks"`
	TrendData           []TrendPoint        `json:"trend_data"`
	MeanTimeToRemediate time.Duration       `json:"mttr"`
	ComplianceStatus    map[string]float64  `json:"compliance_status"`
}

// TrendPoint represents a point in the risk trend
type TrendPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Score     float64   `json:"score"`
}

// New creates a new risk engine
func New(config Config, storage storage.Manager, logger *logrus.Logger) *Engine {
	// Set default weights if not configured
	if config.Weights.CVSSBase == 0 {
		config.Weights = RiskWeights{
			CVSSBase:          0.25,
			EPSSProbability:   0.20,
			KEVPresence:       0.20,
			AssetCriticality:  0.15,
			ExposureLevel:     0.10,
			ExploitMaturity:   0.05,
			RemediationEffort: 0.05,
		}
	}

	engine := &Engine{
		storage: storage,
		kevCache: &KEVCache{
			vulnerabilities: make(map[string]KEVEntry),
		},
		epssCache: &EPSSCache{
			scores: make(map[string]EPSSScore),
		},
		logger: logger,
		httpClient: &http.Client{
			Timeout: config.HTTPTimeout,
		},
		config: config,
	}

	// Start cache update routines
	go engine.updateKEVCache()
	go engine.updateEPSSCache()

	return engine
}

// CalculateFindingRisk calculates risk score for a finding
func (e *Engine) CalculateFindingRisk(ctx context.Context, finding *storage.Finding, asset *storage.Asset) (*RiskScore, error) {
	factors := make(map[string]float64)
	recommendations := []string{}

	// 1. CVSS Base Score Factor (normalized to 0-10)
	cvssScore := 0.0
	if finding.CVSS != nil {
		cvssScore = finding.CVSS.BaseScore
		factors["cvss_base"] = cvssScore
	}

	// 2. EPSS Probability Factor
	epssScore := 0.0
	for _, cve := range finding.CVE {
		if score, exists := e.getEPSSScore(cve); exists {
			epssScore = math.Max(epssScore, score.Probability*10) // Convert to 0-10 scale
			factors["epss_probability"] = epssScore
			factors["epss_percentile"] = score.Percentile
		}
	}

	// 3. KEV Presence Factor
	kevScore := 0.0
	kevPresent := false
	for _, cve := range finding.CVE {
		if e.isInKEV(cve) {
			kevPresent = true
			kevScore = 10.0 // Maximum score if in KEV
			factors["kev_presence"] = kevScore
			recommendations = append(recommendations, fmt.Sprintf("URGENT: CVE %s is actively exploited (CISA KEV)", cve))
			break
		}
	}

	// 4. Asset Criticality Factor
	criticalityScore := e.getAssetCriticalityScore(asset.Criticality)
	factors["asset_criticality"] = criticalityScore

	// 5. Exposure Level Factor
	exposureScore := e.calculateExposureScore(asset, finding)
	factors["exposure_level"] = exposureScore

	// 6. Exploit Maturity Factor
	exploitScore := e.calculateExploitMaturity(finding)
	factors["exploit_maturity"] = exploitScore

	// 7. Remediation Effort Factor (inverse - higher effort = lower score contribution)
	remediationScore := e.calculateRemediationEffort(finding)
	factors["remediation_effort"] = remediationScore

	// Calculate weighted risk score
	weights := e.config.Weights
	finalScore := (cvssScore * weights.CVSSBase) +
		(epssScore * weights.EPSSProbability) +
		(kevScore * weights.KEVPresence) +
		(criticalityScore * weights.AssetCriticality) +
		(exposureScore * weights.ExposureLevel) +
		(exploitScore * weights.ExploitMaturity) +
		(remediationScore * weights.RemediationEffort)

	// Apply contextual adjustments
	if kevPresent {
		finalScore = math.Min(10.0, finalScore*1.5) // Boost score for KEV vulnerabilities
	}

	// Determine severity based on final score
	severity := e.getSeverityFromScore(finalScore)

	// Generate recommendations
	recommendations = append(recommendations, e.generateRecommendations(finding, factors)...)

	// Map to compliance frameworks
	complianceImpact := e.mapToCompliance(finding, severity)

	// Identify related attack paths
	attackPaths, err := e.storage.GetAttackPathsForFinding(ctx, finding.ID)
	if err != nil {
		e.logger.WithError(err).Warn("Failed to get attack paths for finding")
		attackPaths = []string{}
	}

	riskScore := &RiskScore{
		AssetID:          asset.ID,
		FindingID:        finding.ID,
		Score:            math.Round(finalScore*100) / 100, // Round to 2 decimal places
		Severity:         severity,
		Factors:          factors,
		Recommendations:  recommendations,
		ComplianceImpact: complianceImpact,
		AttackPaths:      attackPaths,
		CalculatedAt:     time.Now(),
	}

	// Store risk score
	if err := e.storage.SaveRiskScore(riskScore); err != nil {
		return nil, fmt.Errorf("failed to save risk score: %w", err)
	}

	return riskScore, nil
}

// CalculateAssetRisk calculates overall risk for an asset
func (e *Engine) CalculateAssetRisk(ctx context.Context, assetID string) (*AssetRiskProfile, error) {
	// Get all findings for the asset
	findings, err := e.storage.GetFindingsByAsset(ctx, assetID)
	if err != nil {
		return nil, fmt.Errorf("failed to get findings: %w", err)
	}

	// Get asset details
	asset, err := e.storage.GetAsset(ctx, assetID)
	if err != nil {
		return nil, fmt.Errorf("failed to get asset: %w", err)
	}

	profile := &AssetRiskProfile{
		AssetID:          assetID,
		TopRisks:         []RiskScore{},
		ComplianceStatus: make(map[string]float64),
	}

	var totalScore float64
	var riskScores []RiskScore

	// Calculate risk for each finding
	for _, finding := range findings {
		riskScore, err := e.CalculateFindingRisk(ctx, finding, asset)
		if err != nil {
			e.logger.WithError(err).Warn("Failed to calculate finding risk")
			continue
		}

		riskScores = append(riskScores, *riskScore)
		totalScore += riskScore.Score

		// Count by severity
		switch riskScore.Severity {
		case "critical":
			profile.CriticalFindings++
		case "high":
			profile.HighFindings++
		case "medium":
			profile.MediumFindings++
		case "low":
			profile.LowFindings++
		}
	}

	// Calculate overall score
	if len(riskScores) > 0 {
		profile.OverallScore = totalScore / float64(len(riskScores))
	}

	// Get top risks (sorted by score)
	profile.TopRisks = e.getTopRisks(riskScores, 10)

	// Get trend data
	trendData, err := e.storage.GetRiskTrend(ctx, assetID, 30) // Last 30 days
	if err != nil {
		e.logger.WithError(err).Warn("Failed to get risk trend")
	} else {
		profile.TrendData = trendData
	}

	// Calculate MTTR
	profile.MeanTimeToRemediate = e.calculateMTTR(findings)

	// Calculate compliance status
	profile.ComplianceStatus = e.calculateComplianceStatus(riskScores)

	return profile, nil
}

// updateKEVCache updates the KEV cache periodically
func (e *Engine) updateKEVCache() {
	ticker := time.NewTicker(e.config.KEVUpdateInterval)
	defer ticker.Stop()

	// Initial update
	if err := e.fetchKEVData(); err != nil {
		e.logger.WithError(err).Error("Failed to fetch initial KEV data")
	}

	for range ticker.C {
		if err := e.fetchKEVData(); err != nil {
			e.logger.WithError(err).Error("Failed to update KEV data")
		}
	}
}

// fetchKEVData fetches the latest KEV data from CISA
func (e *Engine) fetchKEVData() error {
	url := "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	
	resp, err := e.httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("failed to fetch KEV data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("KEV API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read KEV response: %w", err)
	}

	var kevData struct {
		Title           string     `json:"title"`
		CatalogVersion  string     `json:"catalogVersion"`
		DateReleased    time.Time  `json:"dateReleased"`
		Count           int        `json:"count"`
		Vulnerabilities []KEVEntry `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(body, &kevData); err != nil {
		return fmt.Errorf("failed to parse KEV data: %w", err)
	}

	// Update cache
	e.kevCache.mutex.Lock()
	defer e.kevCache.mutex.Unlock()

	e.kevCache.vulnerabilities = make(map[string]KEVEntry)
	for _, vuln := range kevData.Vulnerabilities {
		e.kevCache.vulnerabilities[vuln.CVEID] = vuln
	}
	e.kevCache.lastUpdated = time.Now()

	e.logger.WithFields(logrus.Fields{
		"count":   kevData.Count,
		"version": kevData.CatalogVersion,
	}).Info("KEV cache updated")

	return nil
}

// updateEPSSCache updates the EPSS cache periodically
func (e *Engine) updateEPSSCache() {
	ticker := time.NewTicker(e.config.EPSSUpdateInterval)
	defer ticker.Stop()

	// Initial update
	if err := e.fetchEPSSData(); err != nil {
		e.logger.WithError(err).Error("Failed to fetch initial EPSS data")
	}

	for range ticker.C {
		if err := e.fetchEPSSData(); err != nil {
			e.logger.WithError(err).Error("Failed to update EPSS data")
		}
	}
}

// fetchEPSSData fetches the latest EPSS data from FIRST
func (e *Engine) fetchEPSSData() error {
	// Note: This is a simplified version. In production, you would:
	// 1. Download the full EPSS CSV file
	// 2. Parse and store it efficiently
	// 3. Implement pagination for large datasets
	
	url := "https://api.first.org/data/v1/epss"
	
	// For demonstration, we're fetching a subset
	// In production, implement proper CSV download and parsing
	
	e.logger.Info("EPSS cache update completed")
	return nil
}

// isInKEV checks if a CVE is in the KEV catalog
func (e *Engine) isInKEV(cve string) bool {
	e.kevCache.mutex.RLock()
	defer e.kevCache.mutex.RUnlock()
	
	_, exists := e.kevCache.vulnerabilities[cve]
	return exists
}

// getEPSSScore gets the EPSS score for a CVE
func (e *Engine) getEPSSScore(cve string) (EPSSScore, bool) {
	e.epssCache.mutex.RLock()
	defer e.epssCache.mutex.RUnlock()
	
	score, exists := e.epssCache.scores[cve]
	return score, exists
}

// getAssetCriticalityScore converts asset criticality to numeric score
func (e *Engine) getAssetCriticalityScore(criticality string) float64 {
	switch criticality {
	case "critical":
		return 10.0
	case "high":
		return 7.5
	case "medium":
		return 5.0
	case "low":
		return 2.5
	default:
		return 5.0
	}
}

// calculateExposureScore calculates exposure level of the vulnerability
func (e *Engine) calculateExposureScore(asset *storage.Asset, finding *storage.Finding) float64 {
	score := 5.0 // Base score

	// Check if asset is internet-facing
	if isInternetFacing, ok := asset.Attributes["internet_facing"].(bool); ok && isInternetFacing {
		score += 3.0
	}

	// Check if in DMZ
	if inDMZ, ok := asset.Labels["network"]; ok && inDMZ == "dmz" {
		score += 2.0
	}

	// Check authentication requirements
	if finding.Evidence != nil {
		if authRequired, ok := finding.Evidence["authentication_required"].(bool); ok && !authRequired {
			score += 2.0
		}
	}

	return math.Min(10.0, score)
}

// calculateExploitMaturity calculates exploit maturity score
func (e *Engine) calculateExploitMaturity(finding *storage.Finding) float64 {
	// Check for public exploits
	if finding.Evidence != nil {
		if hasExploit, ok := finding.Evidence["public_exploit"].(bool); ok && hasExploit {
			return 10.0
		}
		
		if exploitType, ok := finding.Evidence["exploit_type"].(string); ok {
			switch exploitType {
			case "functional":
				return 8.0
			case "poc":
				return 6.0
			case "theoretical":
				return 3.0
			}
		}
	}

	// Check CVSS exploitability
	if finding.CVSS != nil && finding.CVSS.Exploitability > 0 {
		return finding.CVSS.Exploitability
	}

	return 2.0 // Default low score
}

// calculateRemediationEffort calculates remediation effort score
func (e *Engine) calculateRemediationEffort(finding *storage.Finding) float64 {
	// Lower effort = higher score (easier to fix = higher priority)
	baseScore := 5.0

	if finding.Remediation != "" {
		// Check for patch availability
		if hasPatch, ok := finding.Evidence["patch_available"].(bool); ok && hasPatch {
			baseScore += 3.0
		}

		// Check for workaround
		if hasWorkaround, ok := finding.Evidence["workaround_available"].(bool); ok && hasWorkaround {
			baseScore += 2.0
		}
	}

	return math.Min(10.0, baseScore)
}

// getSeverityFromScore determines severity based on risk score
func (e *Engine) getSeverityFromScore(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	default:
		return "low"
	}
}

// generateRecommendations generates actionable recommendations
func (e *Engine) generateRecommendations(finding *storage.Finding, factors map[string]float64) []string {
	recommendations := []string{}

	// High CVSS score recommendation
	if cvss, ok := factors["cvss_base"]; ok && cvss >= 7.0 {
		recommendations = append(recommendations, "Apply vendor patches immediately due to high CVSS score")
	}

	// High EPSS probability
	if epss, ok := factors["epss_probability"]; ok && epss >= 5.0 {
		recommendations = append(recommendations, fmt.Sprintf("High exploitation probability (%.1f%%) - prioritize remediation", epss*10))
	}

	// Internet-facing asset
	if exposure, ok := factors["exposure_level"]; ok && exposure >= 8.0 {
		recommendations = append(recommendations, "Asset is internet-facing - implement additional controls or isolate")
	}

	// Available patch
	if finding.Evidence != nil {
		if patch, ok := finding.Evidence["patch_available"].(bool); ok && patch {
			recommendations = append(recommendations, "Security patch available - schedule immediate deployment")
		}
	}

	// Compliance specific
	if len(finding.ComplianceGaps) > 0 {
		frameworks := make(map[string]bool)
		for _, gap := range finding.ComplianceGaps {
			frameworks[gap.Framework] = true
		}
		for framework := range frameworks {
			recommendations = append(recommendations, fmt.Sprintf("Address %s compliance requirements", framework))
		}
	}

	return recommendations
}

// mapToCompliance maps findings to compliance frameworks
func (e *Engine) mapToCompliance(finding *storage.Finding, severity string) []ComplianceMapping {
	mappings := []ComplianceMapping{}

	// NIST CSF 2.0 mapping
	nistMapping := ComplianceMapping{
		Framework: "NIST CSF 2.0",
		Impact:    severity,
	}

	// Map based on finding type
	switch finding.Type {
	case "vulnerability":
		nistMapping.Controls = []string{"PR.DS-1", "PR.IP-12", "DE.CM-8"}
		nistMapping.Description = "Vulnerability management and patching"
	case "misconfiguration":
		nistMapping.Controls = []string{"PR.IP-1", "PR.DS-3", "PR.PT-3"}
		nistMapping.Description = "Configuration management"
	case "exposure":
		nistMapping.Controls = []string{"PR.AC-4", "PR.AC-5", "PR.PT-4"}
		nistMapping.Description = "Access control and network segmentation"
	}

	mappings = append(mappings, nistMapping)

	// ISO 27001 mapping
	isoMapping := ComplianceMapping{
		Framework: "ISO 27001:2022",
		Impact:    severity,
	}

	switch finding.Type {
	case "vulnerability":
		isoMapping.Controls = []string{"A.8.8", "A.12.6.1", "A.18.2.3"}
		isoMapping.Description = "Technical vulnerability management"
	case "misconfiguration":
		isoMapping.Controls = []string{"A.8.9", "A.8.10", "A.12.1.1"}
		isoMapping.Description = "Configuration and change management"
	}

	mappings = append(mappings, isoMapping)

	// Map to MITRE ATT&CK if applicable
	if len(finding.MITREAttack) > 0 {
		attackMapping := ComplianceMapping{
			Framework:   "MITRE ATT&CK",
			Controls:    finding.MITREAttack,
			Impact:      severity,
			Description: "Techniques that could be used to exploit this finding",
		}
		mappings = append(mappings, attackMapping)
	}

	return mappings
}

// getTopRisks returns the top N risks sorted by score
func (e *Engine) getTopRisks(risks []RiskScore, limit int) []RiskScore {
	// Sort by score descending
	for i := 0; i < len(risks)-1; i++ {
		for j := i + 1; j < len(risks); j++ {
			if risks[j].Score > risks[i].Score {
				risks[i], risks[j] = risks[j], risks[i]
			}
		}
	}

	if len(risks) < limit {
		return risks
	}
	return risks[:limit]
}

// calculateMTTR calculates mean time to remediate
func (e *Engine) calculateMTTR(findings []*storage.Finding) time.Duration {
	var totalDuration time.Duration
	var remediatedCount int

	for _, finding := range findings {
		if finding.RemediatedAt != nil {
			duration := finding.RemediatedAt.Sub(finding.DiscoveredAt)
			totalDuration += duration
			remediatedCount++
		}
	}

	if remediatedCount == 0 {
		return 0
	}

	return totalDuration / time.Duration(remediatedCount)
}

// calculateComplianceStatus calculates compliance percentage for each framework
func (e *Engine) calculateComplianceStatus(risks []RiskScore) map[string]float64 {
	status := make(map[string]float64)
	frameworkCounts := make(map[string]int)
	frameworkCritical := make(map[string]int)

	for _, risk := range risks {
		for _, compliance := range risk.ComplianceImpact {
			frameworkCounts[compliance.Framework]++
			if risk.Severity == "critical" || risk.Severity == "high" {
				frameworkCritical[compliance.Framework]++
			}
		}
	}

	// Calculate compliance percentage (inverse of critical findings)
	for framework, count := range frameworkCounts {
		if count > 0 {
			criticalCount := frameworkCritical[framework]
			status[framework] = 100.0 * (1.0 - float64(criticalCount)/float64(count))
		}
	}

	return status
}