package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/lib/pq"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"

	"github.com/sovereign-eye/core/pkg/config"
)

// Manager manages all storage backends
type Manager struct {
	postgres      *sql.DB
	elasticsearch *elasticsearch.Client
	neo4j         neo4j.DriverWithContext
	redis         *redis.Client
	logger        *logrus.Logger
}

// Asset represents a discovered asset
type Asset struct {
	ID           string                 `json:"id"`
	TenantID     string                 `json:"tenant_id"`
	Type         string                 `json:"type"` // domain, ip, service, cloud_resource
	Name         string                 `json:"name"`
	Value        string                 `json:"value"`
	Criticality  string                 `json:"criticality"`
	Labels       map[string]string      `json:"labels"`
	Attributes   map[string]interface{} `json:"attributes"`
	DiscoveredAt time.Time              `json:"discovered_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
	LastScanned  *time.Time             `json:"last_scanned,omitempty"`
}

// Finding represents a security finding
type Finding struct {
	ID              string                 `json:"id"`
	AssetID         string                 `json:"asset_id"`
	TenantID        string                 `json:"tenant_id"`
	Type            string                 `json:"type"`
	Severity        string                 `json:"severity"`
	Title           string                 `json:"title"`
	Description     string                 `json:"description"`
	CVE             []string               `json:"cve,omitempty"`
	CVSS            *CVSSScore             `json:"cvss,omitempty"`
	EPSS            *EPSSScore             `json:"epss,omitempty"`
	KEV             bool                   `json:"kev"`
	Remediation     string                 `json:"remediation"`
	Evidence        map[string]interface{} `json:"evidence"`
	Status          string                 `json:"status"`
	RiskScore       float64                `json:"risk_score"`
	MITREAttack     []string               `json:"mitre_attack,omitempty"`
	ComplianceGaps  []ComplianceGap        `json:"compliance_gaps,omitempty"`
	DiscoveredAt    time.Time              `json:"discovered_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
	RemediatedAt    *time.Time             `json:"remediated_at,omitempty"`
}

// CVSSScore represents CVSS scoring
type CVSSScore struct {
	Version      string  `json:"version"`
	BaseScore    float64 `json:"base_score"`
	Vector       string  `json:"vector"`
	Exploitability float64 `json:"exploitability"`
	Impact       float64 `json:"impact"`
}

// EPSSScore represents EPSS probability
type EPSSScore struct {
	Probability float64   `json:"probability"`
	Percentile  float64   `json:"percentile"`
	Date        time.Time `json:"date"`
}

// ComplianceGap represents a compliance framework gap
type ComplianceGap struct {
	Framework string `json:"framework"`
	Control   string `json:"control"`
	Gap       string `json:"gap"`
	Severity  string `json:"severity"`
}

// ScanResult represents scan execution results
type ScanResult struct {
	ID          string                 `json:"id"`
	WorkflowID  string                 `json:"workflow_id"`
	TaskName    string                 `json:"task_name"`
	Tool        string                 `json:"tool"`
	Target      string                 `json:"target"`
	Status      string                 `json:"status"`
	Output      map[string]interface{} `json:"output"`
	RawOutput   string                 `json:"raw_output,omitempty"`
	Findings    []string               `json:"findings"`
	StartTime   time.Time              `json:"start_time"`
	EndTime     time.Time              `json:"end_time"`
	Duration    time.Duration          `json:"duration"`
	Error       string                 `json:"error,omitempty"`
}

// AttackPath represents an attack path in the graph
type AttackPath struct {
	ID          string        `json:"id"`
	TenantID    string        `json:"tenant_id"`
	Source      string        `json:"source"`
	Target      string        `json:"target"`
	Path        []PathNode    `json:"path"`
	Risk        float64       `json:"risk"`
	Likelihood  float64       `json:"likelihood"`
	Impact      float64       `json:"impact"`
	Techniques  []string      `json:"techniques"`
	AnalyzedAt  time.Time     `json:"analyzed_at"`
}

// PathNode represents a node in an attack path
type PathNode struct {
	AssetID       string   `json:"asset_id"`
	Type          string   `json:"type"`
	Vulnerabilities []string `json:"vulnerabilities"`
	Exploits      []string `json:"exploits"`
	Privileges    []string `json:"privileges"`
}

// NewManager creates a new storage manager
func NewManager(config config.StorageConfig) (*Manager, error) {
	manager := &Manager{
		logger: logrus.New(),
	}

	// Initialize PostgreSQL
	if err := manager.initPostgreSQL(config.PostgreSQL); err != nil {
		return nil, fmt.Errorf("failed to initialize PostgreSQL: %w", err)
	}

	// Initialize Elasticsearch
	if err := manager.initElasticsearch(config.Elasticsearch); err != nil {
		return nil, fmt.Errorf("failed to initialize Elasticsearch: %w", err)
	}

	// Initialize Neo4j
	if err := manager.initNeo4j(config.Neo4j); err != nil {
		return nil, fmt.Errorf("failed to initialize Neo4j: %w", err)
	}

	// Initialize Redis
	if err := manager.initRedis(config.Redis); err != nil {
		return nil, fmt.Errorf("failed to initialize Redis: %w", err)
	}

	return manager, nil
}

// initPostgreSQL initializes PostgreSQL connection
func (m *Manager) initPostgreSQL(config config.PostgreSQLConfig) error {
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		config.Host, config.Port, config.Username, config.Password, config.Database, config.SSLMode)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return err
	}

	// Configure connection pool
	db.SetMaxOpenConns(config.MaxConnections)
	db.SetMaxIdleConns(config.MaxIdleConnections)
	db.SetConnMaxLifetime(config.ConnectionLifetime)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return err
	}

	m.postgres = db
	m.logger.Info("PostgreSQL connection established")

	// Create tables if not exist
	if err := m.createPostgreSQLSchema(); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	return nil
}

// initElasticsearch initializes Elasticsearch client
func (m *Manager) initElasticsearch(config config.ElasticsearchConfig) error {
	cfg := elasticsearch.Config{
		Addresses:     config.Addresses,
		Username:      config.Username,
		Password:      config.Password,
		RetryOnStatus: []int{502, 503, 504, 429},
		MaxRetries:    config.MaxRetries,
		EnableMetrics: true,
	}

	client, err := elasticsearch.NewClient(cfg)
	if err != nil {
		return err
	}

	// Test connection
	res, err := client.Info()
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.IsError() {
		return fmt.Errorf("elasticsearch error: %s", res.String())
	}

	m.elasticsearch = client
	m.logger.Info("Elasticsearch connection established")

	// Create indices if not exist
	if err := m.createElasticsearchIndices(config.IndexPrefix); err != nil {
		return fmt.Errorf("failed to create indices: %w", err)
	}

	return nil
}

// initNeo4j initializes Neo4j driver
func (m *Manager) initNeo4j(config config.Neo4jConfig) error {
	driver, err := neo4j.NewDriverWithContext(
		config.URI,
		neo4j.BasicAuth(config.Username, config.Password, ""),
		func(c *neo4j.Config) {
			c.Encrypted = config.Encrypted
			c.MaxConnectionLifetime = config.MaxConnectionLifetime
			c.MaxConnectionPoolSize = config.MaxConnectionPoolSize
		})
	if err != nil {
		return err
	}

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := driver.VerifyConnectivity(ctx); err != nil {
		return err
	}

	m.neo4j = driver
	m.logger.Info("Neo4j connection established")

	// Create constraints and indices
	if err := m.createNeo4jSchema(ctx); err != nil {
		return fmt.Errorf("failed to create Neo4j schema: %w", err)
	}

	return nil
}

// initRedis initializes Redis client
func (m *Manager) initRedis(config config.RedisConfig) error {
	client := redis.NewClient(&redis.Options{
		Addr:         config.Address,
		Password:     config.Password,
		DB:           config.Database,
		PoolSize:     config.PoolSize,
		MinIdleConns: config.MinIdleConns,
		MaxRetries:   config.MaxRetries,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return err
	}

	m.redis = client
	m.logger.Info("Redis connection established")

	return nil
}

// createPostgreSQLSchema creates the database schema
func (m *Manager) createPostgreSQLSchema() error {
	schema := `
	-- Enable TimescaleDB extension
	CREATE EXTENSION IF NOT EXISTS timescaledb;

	-- Assets table
	CREATE TABLE IF NOT EXISTS assets (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		tenant_id UUID NOT NULL,
		type VARCHAR(50) NOT NULL,
		name VARCHAR(255) NOT NULL,
		value TEXT NOT NULL,
		criticality VARCHAR(20) DEFAULT 'medium',
		labels JSONB DEFAULT '{}',
		attributes JSONB DEFAULT '{}',
		discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		last_scanned TIMESTAMPTZ,
		UNIQUE(tenant_id, type, value)
	);

	-- Create hypertable for time-series data
	SELECT create_hypertable('assets', 'discovered_at', if_not_exists => TRUE);

	-- Findings table
	CREATE TABLE IF NOT EXISTS findings (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
		tenant_id UUID NOT NULL,
		type VARCHAR(100) NOT NULL,
		severity VARCHAR(20) NOT NULL,
		title TEXT NOT NULL,
		description TEXT,
		cve TEXT[],
		cvss JSONB,
		epss JSONB,
		kev BOOLEAN DEFAULT FALSE,
		remediation TEXT,
		evidence JSONB DEFAULT '{}',
		status VARCHAR(50) DEFAULT 'open',
		risk_score DECIMAL(3,1),
		mitre_attack TEXT[],
		compliance_gaps JSONB DEFAULT '[]',
		discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		remediated_at TIMESTAMPTZ
	);

	-- Create hypertable for findings
	SELECT create_hypertable('findings', 'discovered_at', if_not_exists => TRUE);

	-- Scan results table
	CREATE TABLE IF NOT EXISTS scan_results (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		workflow_id UUID NOT NULL,
		task_name VARCHAR(255) NOT NULL,
		tool VARCHAR(100) NOT NULL,
		target TEXT NOT NULL,
		status VARCHAR(50) NOT NULL,
		output JSONB DEFAULT '{}',
		findings UUID[],
		start_time TIMESTAMPTZ NOT NULL,
		end_time TIMESTAMPTZ NOT NULL,
		duration INTERVAL,
		error TEXT
	);

	-- Create hypertable for scan results
	SELECT create_hypertable('scan_results', 'start_time', if_not_exists => TRUE);

	-- Risk scores table
	CREATE TABLE IF NOT EXISTS risk_scores (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
		tenant_id UUID NOT NULL,
		score DECIMAL(3,1) NOT NULL,
		factors JSONB NOT NULL,
		calculated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	-- Create hypertable for risk scores
	SELECT create_hypertable('risk_scores', 'calculated_at', if_not_exists => TRUE);

	-- Workflows table
	CREATE TABLE IF NOT EXISTS workflows (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		tenant_id UUID NOT NULL,
		name VARCHAR(255) NOT NULL,
		specification JSONB NOT NULL,
		state VARCHAR(50) NOT NULL,
		parameters JSONB DEFAULT '{}',
		task_states JSONB DEFAULT '{}',
		start_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		end_time TIMESTAMPTZ,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	-- Create indices
	CREATE INDEX IF NOT EXISTS idx_assets_tenant_id ON assets(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(type);
	CREATE INDEX IF NOT EXISTS idx_assets_criticality ON assets(criticality);
	CREATE INDEX IF NOT EXISTS idx_assets_labels ON assets USING GIN(labels);
	
	CREATE INDEX IF NOT EXISTS idx_findings_tenant_id ON findings(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
	CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
	CREATE INDEX IF NOT EXISTS idx_findings_kev ON findings(kev) WHERE kev = TRUE;
	CREATE INDEX IF NOT EXISTS idx_findings_risk_score ON findings(risk_score);
	
	CREATE INDEX IF NOT EXISTS idx_scan_results_workflow_id ON scan_results(workflow_id);
	CREATE INDEX IF NOT EXISTS idx_scan_results_status ON scan_results(status);
	
	CREATE INDEX IF NOT EXISTS idx_workflows_tenant_id ON workflows(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_workflows_state ON workflows(state);

	-- Enable compression on older data
	ALTER TABLE assets SET (
		timescaledb.compress,
		timescaledb.compress_segmentby = 'tenant_id'
	);

	ALTER TABLE findings SET (
		timescaledb.compress,
		timescaledb.compress_segmentby = 'tenant_id'
	);

	-- Add compression policies
	SELECT add_compression_policy('assets', INTERVAL '7 days', if_not_exists => TRUE);
	SELECT add_compression_policy('findings', INTERVAL '7 days', if_not_exists => TRUE);
	SELECT add_compression_policy('scan_results', INTERVAL '30 days', if_not_exists => TRUE);
	SELECT add_compression_policy('risk_scores', INTERVAL '30 days', if_not_exists => TRUE);

	-- Add retention policies
	SELECT add_retention_policy('scan_results', INTERVAL '90 days', if_not_exists => TRUE);
	SELECT add_retention_policy('risk_scores', INTERVAL '365 days', if_not_exists => TRUE);
	`

	_, err := m.postgres.Exec(schema)
	return err
}

// Close closes all storage connections
func (m *Manager) Close() error {
	if m.postgres != nil {
		if err := m.postgres.Close(); err != nil {
			m.logger.WithError(err).Error("Failed to close PostgreSQL connection")
		}
	}

	if m.neo4j != nil {
		if err := m.neo4j.Close(context.Background()); err != nil {
			m.logger.WithError(err).Error("Failed to close Neo4j connection")
		}
	}

	if m.redis != nil {
		if err := m.redis.Close(); err != nil {
			m.logger.WithError(err).Error("Failed to close Redis connection")
		}
	}

	return nil
}

// Health checks the health of all storage backends
func (m *Manager) Health() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check PostgreSQL
	if err := m.postgres.PingContext(ctx); err != nil {
		return fmt.Errorf("postgresql health check failed: %w", err)
	}

	// Check Elasticsearch
	res, err := m.elasticsearch.Ping()
	if err != nil {
		return fmt.Errorf("elasticsearch health check failed: %w", err)
	}
	defer res.Body.Close()
	if res.IsError() {
		return fmt.Errorf("elasticsearch health check failed: %s", res.String())
	}

	// Check Neo4j
	if err := m.neo4j.VerifyConnectivity(ctx); err != nil {
		return fmt.Errorf("neo4j health check failed: %w", err)
	}

	// Check Redis
	if err := m.redis.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis health check failed: %w", err)
	}

	return nil
}

// SaveAsset saves an asset to the database
func (m *Manager) SaveAsset(asset *Asset) error {
	query := `
		INSERT INTO assets (id, tenant_id, type, name, value, criticality, labels, attributes, discovered_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (tenant_id, type, value) 
		DO UPDATE SET 
			name = EXCLUDED.name,
			criticality = EXCLUDED.criticality,
			labels = EXCLUDED.labels,
			attributes = EXCLUDED.attributes,
			updated_at = EXCLUDED.updated_at
		RETURNING id
	`

	labelsJSON, _ := json.Marshal(asset.Labels)
	attributesJSON, _ := json.Marshal(asset.Attributes)

	err := m.postgres.QueryRow(
		query,
		asset.ID,
		asset.TenantID,
		asset.Type,
		asset.Name,
		asset.Value,
		asset.Criticality,
		labelsJSON,
		attributesJSON,
		asset.DiscoveredAt,
		asset.UpdatedAt,
	).Scan(&asset.ID)

	if err != nil {
		return fmt.Errorf("failed to save asset: %w", err)
	}

	// Also save to Neo4j for graph analysis
	ctx := context.Background()
	session := m.neo4j.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	_, err = session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		query := `
			MERGE (a:Asset {id: $id})
			SET a.tenant_id = $tenant_id,
				a.type = $type,
				a.name = $name,
				a.value = $value,
				a.criticality = $criticality,
				a.discovered_at = $discovered_at,
				a.updated_at = $updated_at
		`
		_, err := tx.Run(ctx, query, map[string]interface{}{
			"id":            asset.ID,
			"tenant_id":     asset.TenantID,
			"type":          asset.Type,
			"name":          asset.Name,
			"value":         asset.Value,
			"criticality":   asset.Criticality,
			"discovered_at": asset.DiscoveredAt.Unix(),
			"updated_at":    asset.UpdatedAt.Unix(),
		})
		return nil, err
	})

	return err
}

// Additional storage methods would be implemented here...