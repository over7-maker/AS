package graph

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/sirupsen/logrus"

	"github.com/sovereign-eye/core/internal/storage"
)

// Analyzer performs attack path analysis using graph algorithms
type Analyzer struct {
	driver neo4j.DriverWithContext
	logger *logrus.Logger
	config Config
}

// Config holds graph analyzer configuration
type Config struct {
	MaxPathLength      int
	MaxPaths           int
	ParallelQueries    int
	QueryTimeout       time.Duration
	CrownJewelLabels   []string
	HighValueTargets   []string
}

// AttackPath represents a potential attack path
type AttackPath struct {
	ID             string         `json:"id"`
	Source         Node           `json:"source"`
	Target         Node           `json:"target"`
	Path           []PathSegment  `json:"path"`
	TotalRisk      float64        `json:"total_risk"`
	Likelihood     float64        `json:"likelihood"`
	Impact         float64        `json:"impact"`
	Length         int            `json:"length"`
	Techniques     []MITRETechnique `json:"techniques"`
	Remediations   []Remediation  `json:"remediations"`
	VisualizationData map[string]interface{} `json:"visualization_data"`
}

// Node represents a node in the attack graph
type Node struct {
	ID           string                 `json:"id"`
	Type         string                 `json:"type"`
	Name         string                 `json:"name"`
	Properties   map[string]interface{} `json:"properties"`
	Risk         float64                `json:"risk"`
	Compromised  bool                   `json:"compromised"`
}

// PathSegment represents a segment in an attack path
type PathSegment struct {
	From         Node          `json:"from"`
	To           Node          `json:"to"`
	Relationship Relationship  `json:"relationship"`
	Probability  float64       `json:"probability"`
	Techniques   []string      `json:"techniques"`
}

// Relationship represents an edge in the attack graph
type Relationship struct {
	Type         string                 `json:"type"`
	Properties   map[string]interface{} `json:"properties"`
	Risk         float64                `json:"risk"`
}

// MITRETechnique represents a MITRE ATT&CK technique
type MITRETechnique struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Tactic      string   `json:"tactic"`
	Description string   `json:"description"`
	Mitigations []string `json:"mitigations"`
}

// Remediation represents a remediation action
type Remediation struct {
	Type        string  `json:"type"`
	Description string  `json:"description"`
	Priority    string  `json:"priority"`
	Cost        string  `json:"cost"`
	Effort      string  `json:"effort"`
	Impact      float64 `json:"impact"`
}

// New creates a new graph analyzer
func New(driver neo4j.DriverWithContext, config Config, logger *logrus.Logger) *Analyzer {
	return &Analyzer{
		driver: driver,
		logger: logger,
		config: config,
	}
}

// InitializeSchema creates necessary constraints and indexes in Neo4j
func (a *Analyzer) InitializeSchema(ctx context.Context) error {
	session := a.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	queries := []string{
		// Node constraints
		"CREATE CONSTRAINT IF NOT EXISTS FOR (a:Asset) REQUIRE a.id IS UNIQUE",
		"CREATE CONSTRAINT IF NOT EXISTS FOR (s:Service) REQUIRE s.id IS UNIQUE",
		"CREATE CONSTRAINT IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE",
		"CREATE CONSTRAINT IF NOT EXISTS FOR (u:User) REQUIRE u.id IS UNIQUE",
		"CREATE CONSTRAINT IF NOT EXISTS FOR (g:Group) REQUIRE g.id IS UNIQUE",
		
		// Indexes for performance
		"CREATE INDEX IF NOT EXISTS FOR (a:Asset) ON (a.tenant_id)",
		"CREATE INDEX IF NOT EXISTS FOR (a:Asset) ON (a.criticality)",
		"CREATE INDEX IF NOT EXISTS FOR (v:Vulnerability) ON (v.cve)",
		"CREATE INDEX IF NOT EXISTS FOR (v:Vulnerability) ON (v.severity)",
		
		// Full-text indexes
		"CREATE FULLTEXT INDEX asset_search IF NOT EXISTS FOR (a:Asset) ON EACH [a.name, a.value]",
		"CREATE FULLTEXT INDEX vuln_search IF NOT EXISTS FOR (v:Vulnerability) ON EACH [v.title, v.description]",
	}

	for _, query := range queries {
		_, err := session.Run(ctx, query, nil)
		if err != nil {
			return fmt.Errorf("failed to execute schema query: %w", err)
		}
	}

	a.logger.Info("Graph schema initialized successfully")
	return nil
}

// AnalyzeAttackPaths finds potential attack paths to high-value targets
func (a *Analyzer) AnalyzeAttackPaths(ctx context.Context, tenantID string) ([]AttackPath, error) {
	session := a.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	// Find crown jewel assets
	crownJewels, err := a.findCrownJewels(ctx, session, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to find crown jewels: %w", err)
	}

	// Find potential entry points
	entryPoints, err := a.findEntryPoints(ctx, session, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to find entry points: %w", err)
	}

	var allPaths []AttackPath

	// Analyze paths from each entry point to each crown jewel
	for _, entryPoint := range entryPoints {
		for _, crownJewel := range crownJewels {
			paths, err := a.findPaths(ctx, session, entryPoint, crownJewel)
			if err != nil {
				a.logger.WithError(err).Warn("Failed to find paths")
				continue
			}
			allPaths = append(allPaths, paths...)
		}
	}

	// Rank paths by risk
	a.rankPaths(allPaths)

	// Limit to top paths
	if len(allPaths) > a.config.MaxPaths {
		allPaths = allPaths[:a.config.MaxPaths]
	}

	// Enrich paths with additional data
	for i := range allPaths {
		a.enrichPath(&allPaths[i])
	}

	return allPaths, nil
}

// findCrownJewels identifies high-value target assets
func (a *Analyzer) findCrownJewels(ctx context.Context, session neo4j.SessionWithContext, tenantID string) ([]Node, error) {
	query := `
		MATCH (a:Asset {tenant_id: $tenant_id})
		WHERE a.criticality = 'critical' 
			OR any(label IN $crown_jewel_labels WHERE label IN labels(a))
			OR a.name IN $high_value_targets
		RETURN a.id as id, a.name as name, a.type as type, 
			   properties(a) as properties, a.criticality as criticality
		LIMIT 100
	`

	result, err := session.Run(ctx, query, map[string]interface{}{
		"tenant_id":          tenantID,
		"crown_jewel_labels": a.config.CrownJewelLabels,
		"high_value_targets": a.config.HighValueTargets,
	})
	if err != nil {
		return nil, err
	}

	var nodes []Node
	for result.Next(ctx) {
		record := result.Record()
		node := Node{
			ID:         record.Values[0].(string),
			Name:       record.Values[1].(string),
			Type:       record.Values[2].(string),
			Properties: record.Values[3].(map[string]interface{}),
			Risk:       a.calculateNodeRisk(record.Values[4].(string)),
		}
		nodes = append(nodes, node)
	}

	return nodes, result.Err()
}

// findEntryPoints identifies potential attack entry points
func (a *Analyzer) findEntryPoints(ctx context.Context, session neo4j.SessionWithContext, tenantID string) ([]Node, error) {
	query := `
		MATCH (a:Asset {tenant_id: $tenant_id})
		WHERE a.internet_facing = true 
			OR exists((a)-[:EXPOSED_TO]->(:Internet))
			OR a.type IN ['domain', 'public_ip', 'cdn']
		OPTIONAL MATCH (a)-[:HAS_VULNERABILITY]->(v:Vulnerability)
		WITH a, count(v) as vuln_count, 
			 max(CASE WHEN v.severity = 'critical' THEN 4
			          WHEN v.severity = 'high' THEN 3
			          WHEN v.severity = 'medium' THEN 2
			          WHEN v.severity = 'low' THEN 1
			          ELSE 0 END) as max_severity
		RETURN a.id as id, a.name as name, a.type as type,
			   properties(a) as properties, vuln_count, max_severity
		ORDER BY max_severity DESC, vuln_count DESC
		LIMIT 100
	`

	result, err := session.Run(ctx, query, map[string]interface{}{
		"tenant_id": tenantID,
	})
	if err != nil {
		return nil, err
	}

	var nodes []Node
	for result.Next(ctx) {
		record := result.Record()
		vulnCount := record.Values[4].(int64)
		maxSeverity := record.Values[5].(int64)
		
		node := Node{
			ID:         record.Values[0].(string),
			Name:       record.Values[1].(string),
			Type:       record.Values[2].(string),
			Properties: record.Values[3].(map[string]interface{}),
			Risk:       float64(vulnCount)*0.5 + float64(maxSeverity)*2.5,
		}
		nodes = append(nodes, node)
	}

	return nodes, result.Err()
}

// findPaths finds attack paths between two nodes
func (a *Analyzer) findPaths(ctx context.Context, session neo4j.SessionWithContext, source, target Node) ([]AttackPath, error) {
	// Use multiple algorithms for comprehensive analysis
	var allPaths []AttackPath

	// 1. Shortest path (most direct attack)
	shortestPaths, err := a.findShortestPaths(ctx, session, source, target)
	if err != nil {
		a.logger.WithError(err).Warn("Failed to find shortest paths")
	} else {
		allPaths = append(allPaths, shortestPaths...)
	}

	// 2. Paths through vulnerabilities
	vulnPaths, err := a.findVulnerabilityPaths(ctx, session, source, target)
	if err != nil {
		a.logger.WithError(err).Warn("Failed to find vulnerability paths")
	} else {
		allPaths = append(allPaths, vulnPaths...)
	}

	// 3. Lateral movement paths
	lateralPaths, err := a.findLateralMovementPaths(ctx, session, source, target)
	if err != nil {
		a.logger.WithError(err).Warn("Failed to find lateral movement paths")
	} else {
		allPaths = append(allPaths, lateralPaths...)
	}

	// 4. Privilege escalation paths
	privEscPaths, err := a.findPrivilegeEscalationPaths(ctx, session, source, target)
	if err != nil {
		a.logger.WithError(err).Warn("Failed to find privilege escalation paths")
	} else {
		allPaths = append(allPaths, privEscPaths...)
	}

	return allPaths, nil
}

// findShortestPaths finds the shortest attack paths
func (a *Analyzer) findShortestPaths(ctx context.Context, session neo4j.SessionWithContext, source, target Node) ([]AttackPath, error) {
	query := `
		MATCH path = allShortestPaths(
			(source:Asset {id: $source_id}),
			(target:Asset {id: $target_id})
		)
		WHERE length(path) <= $max_length
		UNWIND nodes(path) as n
		OPTIONAL MATCH (n)-[:HAS_VULNERABILITY]->(v:Vulnerability)
		WITH path, collect(DISTINCT v) as vulnerabilities
		RETURN 
			[n in nodes(path) | {id: n.id, name: n.name, type: n.type}] as nodes,
			[r in relationships(path) | {type: type(r), properties: properties(r)}] as relationships,
			vulnerabilities,
			length(path) as path_length
		LIMIT 10
	`

	result, err := session.Run(ctx, query, map[string]interface{}{
		"source_id":  source.ID,
		"target_id":  target.ID,
		"max_length": a.config.MaxPathLength,
	})
	if err != nil {
		return nil, err
	}

	var paths []AttackPath
	for result.Next(ctx) {
		record := result.Record()
		paths = append(paths, a.constructPath(source, target, record))
	}

	return paths, result.Err()
}

// findVulnerabilityPaths finds paths that exploit vulnerabilities
func (a *Analyzer) findVulnerabilityPaths(ctx context.Context, session neo4j.SessionWithContext, source, target Node) ([]AttackPath, error) {
	query := `
		MATCH path = (source:Asset {id: $source_id})-[:HAS_VULNERABILITY|CONNECTS_TO|CAN_ACCESS|AUTHENTICATES_TO*1..` + 
		fmt.Sprintf("%d", a.config.MaxPathLength) + `]-(target:Asset {id: $target_id})
		WHERE any(n IN nodes(path) WHERE (n:Asset AND exists((n)-[:HAS_VULNERABILITY]->(:Vulnerability))))
		WITH path
		LIMIT 20
		UNWIND nodes(path) as n
		OPTIONAL MATCH (n)-[:HAS_VULNERABILITY]->(v:Vulnerability)
		WITH path, collect(DISTINCT v) as vulnerabilities
		RETURN 
			[n in nodes(path) | {id: n.id, name: n.name, type: n.type}] as nodes,
			[r in relationships(path) | {type: type(r), properties: properties(r)}] as relationships,
			vulnerabilities,
			length(path) as path_length
		ORDER BY size(vulnerabilities) DESC
		LIMIT 10
	`

	result, err := session.Run(ctx, query, map[string]interface{}{
		"source_id": source.ID,
		"target_id": target.ID,
	})
	if err != nil {
		return nil, err
	}

	var paths []AttackPath
	for result.Next(ctx) {
		record := result.Record()
		paths = append(paths, a.constructPath(source, target, record))
	}

	return paths, result.Err()
}

// findLateralMovementPaths finds paths using lateral movement techniques
func (a *Analyzer) findLateralMovementPaths(ctx context.Context, session neo4j.SessionWithContext, source, target Node) ([]AttackPath, error) {
	query := `
		MATCH path = (source:Asset {id: $source_id})-[:SAME_NETWORK|SHARES_CREDENTIAL|TRUSTS|CAN_EXECUTE_ON*1..` +
		fmt.Sprintf("%d", a.config.MaxPathLength) + `]-(target:Asset {id: $target_id})
		WITH path
		LIMIT 10
		RETURN 
			[n in nodes(path) | {id: n.id, name: n.name, type: n.type, 
				compromised: CASE WHEN exists(n.compromised) THEN n.compromised ELSE false END}] as nodes,
			[r in relationships(path) | {type: type(r), properties: properties(r)}] as relationships,
			length(path) as path_length
	`

	result, err := session.Run(ctx, query, map[string]interface{}{
		"source_id": source.ID,
		"target_id": target.ID,
	})
	if err != nil {
		return nil, err
	}

	var paths []AttackPath
	for result.Next(ctx) {
		record := result.Record()
		path := a.constructPath(source, target, record)
		
		// Add lateral movement techniques
		path.Techniques = append(path.Techniques, MITRETechnique{
			ID:          "T1021",
			Name:        "Remote Services",
			Tactic:      "Lateral Movement",
			Description: "Adversaries may use valid accounts to interact with remote systems",
		})
		
		paths = append(paths, path)
	}

	return paths, result.Err()
}

// findPrivilegeEscalationPaths finds paths using privilege escalation
func (a *Analyzer) findPrivilegeEscalationPaths(ctx context.Context, session neo4j.SessionWithContext, source, target Node) ([]AttackPath, error) {
	query := `
		MATCH (source:Asset {id: $source_id})
		MATCH (target:Asset {id: $target_id})
		MATCH path = (source)-[:HAS_ACCESS_TO|CAN_ESCALATE_TO|MEMBER_OF|ADMINISTERS*1..` +
		fmt.Sprintf("%d", a.config.MaxPathLength) + `]-(target)
		WHERE any(r IN relationships(path) WHERE type(r) IN ['CAN_ESCALATE_TO', 'ADMINISTERS'])
		WITH path
		LIMIT 10
		RETURN 
			[n in nodes(path) | {id: n.id, name: n.name, type: n.type,
				privileges: CASE WHEN exists(n.privileges) THEN n.privileges ELSE [] END}] as nodes,
			[r in relationships(path) | {type: type(r), properties: properties(r)}] as relationships,
			length(path) as path_length
	`

	result, err := session.Run(ctx, query, map[string]interface{}{
		"source_id": source.ID,
		"target_id": target.ID,
	})
	if err != nil {
		return nil, err
	}

	var paths []AttackPath
	for result.Next(ctx) {
		record := result.Record()
		path := a.constructPath(source, target, record)
		
		// Add privilege escalation techniques
		path.Techniques = append(path.Techniques, MITRETechnique{
			ID:          "T1068",
			Name:        "Exploitation for Privilege Escalation",
			Tactic:      "Privilege Escalation",
			Description: "Adversaries may exploit vulnerabilities to elevate privileges",
		})
		
		paths = append(paths, path)
	}

	return paths, result.Err()
}

// constructPath constructs an AttackPath from query results
func (a *Analyzer) constructPath(source, target Node, record *neo4j.Record) AttackPath {
	nodes := record.Values[0].([]interface{})
	relationships := record.Values[1].([]interface{})
	pathLength := record.Values[2].(int64)
	
	var segments []PathSegment
	
	// Build path segments
	for i := 0; i < len(relationships); i++ {
		rel := relationships[i].(map[string]interface{})
		fromNode := a.convertNode(nodes[i].(map[string]interface{}))
		toNode := a.convertNode(nodes[i+1].(map[string]interface{}))
		
		segment := PathSegment{
			From: fromNode,
			To:   toNode,
			Relationship: Relationship{
				Type:       rel["type"].(string),
				Properties: rel["properties"].(map[string]interface{}),
				Risk:       a.calculateRelationshipRisk(rel["type"].(string)),
			},
			Probability: a.calculateSegmentProbability(fromNode, toNode, rel),
		}
		
		segments = append(segments, segment)
	}
	
	// Calculate path metrics
	totalRisk := a.calculatePathRisk(segments)
	likelihood := a.calculatePathLikelihood(segments)
	impact := a.calculateImpact(target)
	
	return AttackPath{
		ID:         fmt.Sprintf("%s-%s-%d", source.ID, target.ID, time.Now().Unix()),
		Source:     source,
		Target:     target,
		Path:       segments,
		TotalRisk:  totalRisk,
		Likelihood: likelihood,
		Impact:     impact,
		Length:     int(pathLength),
	}
}

// convertNode converts a map to a Node
func (a *Analyzer) convertNode(nodeMap map[string]interface{}) Node {
	node := Node{
		ID:   nodeMap["id"].(string),
		Name: nodeMap["name"].(string),
		Type: nodeMap["type"].(string),
	}
	
	if compromised, ok := nodeMap["compromised"].(bool); ok {
		node.Compromised = compromised
	}
	
	return node
}

// calculateNodeRisk calculates risk score for a node
func (a *Analyzer) calculateNodeRisk(criticality string) float64 {
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

// calculateRelationshipRisk calculates risk for a relationship type
func (a *Analyzer) calculateRelationshipRisk(relType string) float64 {
	riskMap := map[string]float64{
		"HAS_VULNERABILITY":  8.0,
		"EXPOSED_TO":        7.0,
		"CAN_ACCESS":        6.0,
		"AUTHENTICATES_TO":  5.0,
		"SAME_NETWORK":      4.0,
		"CONNECTS_TO":       3.0,
		"TRUSTS":           6.0,
		"CAN_ESCALATE_TO":  8.0,
		"ADMINISTERS":      7.0,
		"CAN_EXECUTE_ON":   7.0,
		"SHARES_CREDENTIAL": 8.0,
	}
	
	if risk, ok := riskMap[relType]; ok {
		return risk
	}
	return 5.0
}

// calculateSegmentProbability calculates exploitation probability for a segment
func (a *Analyzer) calculateSegmentProbability(from, to Node, rel map[string]interface{}) float64 {
	baseProbability := 0.5
	
	// Adjust based on relationship type
	relType := rel["type"].(string)
	switch relType {
	case "HAS_VULNERABILITY":
		baseProbability = 0.7
	case "EXPOSED_TO":
		baseProbability = 0.8
	case "CAN_ESCALATE_TO":
		baseProbability = 0.6
	case "SHARES_CREDENTIAL":
		baseProbability = 0.9
	}
	
	// Adjust based on node compromise status
	if from.Compromised {
		baseProbability *= 1.5
	}
	
	return math.Min(baseProbability, 1.0)
}

// calculatePathRisk calculates total risk for a path
func (a *Analyzer) calculatePathRisk(segments []PathSegment) float64 {
	if len(segments) == 0 {
		return 0.0
	}
	
	totalRisk := 0.0
	for _, segment := range segments {
		totalRisk += segment.Relationship.Risk * segment.Probability
	}
	
	// Normalize by path length
	return totalRisk / float64(len(segments))
}

// calculatePathLikelihood calculates likelihood of successful exploitation
func (a *Analyzer) calculatePathLikelihood(segments []PathSegment) float64 {
	if len(segments) == 0 {
		return 0.0
	}
	
	// Chain probability (all segments must succeed)
	likelihood := 1.0
	for _, segment := range segments {
		likelihood *= segment.Probability
	}
	
	// Apply decay factor for longer paths
	decayFactor := math.Exp(-0.1 * float64(len(segments)))
	
	return likelihood * decayFactor
}

// calculateImpact calculates impact of compromising the target
func (a *Analyzer) calculateImpact(target Node) float64 {
	baseImpact := target.Risk
	
	// Additional factors could be considered:
	// - Number of dependent systems
	// - Data sensitivity
	// - Business criticality
	
	return math.Min(baseImpact * 1.2, 10.0)
}

// rankPaths sorts paths by risk score
func (a *Analyzer) rankPaths(paths []AttackPath) {
	// Sort by combined risk score (risk * likelihood * impact)
	for i := 0; i < len(paths)-1; i++ {
		for j := i + 1; j < len(paths); j++ {
			scoreI := paths[i].TotalRisk * paths[i].Likelihood * paths[i].Impact
			scoreJ := paths[j].TotalRisk * paths[j].Likelihood * paths[j].Impact
			
			if scoreJ > scoreI {
				paths[i], paths[j] = paths[j], paths[i]
			}
		}
	}
}

// enrichPath adds additional context to an attack path
func (a *Analyzer) enrichPath(path *AttackPath) {
	// Add MITRE techniques based on path characteristics
	a.mapToMITRETechniques(path)
	
	// Generate remediation recommendations
	a.generateRemediations(path)
	
	// Add visualization data
	a.addVisualizationData(path)
}

// mapToMITRETechniques maps path segments to MITRE ATT&CK techniques
func (a *Analyzer) mapToMITRETechniques(path *AttackPath) {
	techniqueMap := map[string]MITRETechnique{
		"HAS_VULNERABILITY": {
			ID:     "T1190",
			Name:   "Exploit Public-Facing Application",
			Tactic: "Initial Access",
		},
		"SHARES_CREDENTIAL": {
			ID:     "T1078",
			Name:   "Valid Accounts",
			Tactic: "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
		},
		"CAN_ESCALATE_TO": {
			ID:     "T1548",
			Name:   "Abuse Elevation Control Mechanism",
			Tactic: "Privilege Escalation, Defense Evasion",
		},
		"SAME_NETWORK": {
			ID:     "T1021",
			Name:   "Remote Services",
			Tactic: "Lateral Movement",
		},
	}
	
	seen := make(map[string]bool)
	
	for _, segment := range path.Path {
		relType := segment.Relationship.Type
		if technique, exists := techniqueMap[relType]; exists {
			if !seen[technique.ID] {
				path.Techniques = append(path.Techniques, technique)
				seen[technique.ID] = true
			}
		}
	}
}

// generateRemediations generates remediation recommendations
func (a *Analyzer) generateRemediations(path *AttackPath) {
	remediations := []Remediation{}
	
	// Analyze each segment for remediation opportunities
	for _, segment := range path.Path {
		switch segment.Relationship.Type {
		case "HAS_VULNERABILITY":
			remediations = append(remediations, Remediation{
				Type:        "patch",
				Description: fmt.Sprintf("Apply security patches to %s", segment.From.Name),
				Priority:    "high",
				Cost:        "low",
				Effort:      "medium",
				Impact:      segment.Probability * 0.9, // Patching is highly effective
			})
			
		case "EXPOSED_TO":
			remediations = append(remediations, Remediation{
				Type:        "network_segmentation",
				Description: fmt.Sprintf("Implement network segmentation between %s and %s", segment.From.Name, segment.To.Name),
				Priority:    "high",
				Cost:        "medium",
				Effort:      "high",
				Impact:      0.8,
			})
			
		case "SHARES_CREDENTIAL":
			remediations = append(remediations, Remediation{
				Type:        "credential_rotation",
				Description: fmt.Sprintf("Rotate shared credentials between %s and %s", segment.From.Name, segment.To.Name),
				Priority:    "critical",
				Cost:        "low",
				Effort:      "low",
				Impact:      0.95,
			})
			
		case "CAN_ESCALATE_TO":
			remediations = append(remediations, Remediation{
				Type:        "privilege_reduction",
				Description: fmt.Sprintf("Implement least privilege for %s", segment.From.Name),
				Priority:    "high",
				Cost:        "low",
				Effort:      "medium",
				Impact:      0.7,
			})
		}
	}
	
	// Remove duplicates and sort by impact
	path.Remediations = a.deduplicateAndSortRemediations(remediations)
}

// deduplicateAndSortRemediations removes duplicates and sorts by impact
func (a *Analyzer) deduplicateAndSortRemediations(remediations []Remediation) []Remediation {
	seen := make(map[string]bool)
	unique := []Remediation{}
	
	for _, r := range remediations {
		key := r.Type + ":" + r.Description
		if !seen[key] {
			unique = append(unique, r)
			seen[key] = true
		}
	}
	
	// Sort by impact descending
	for i := 0; i < len(unique)-1; i++ {
		for j := i + 1; j < len(unique); j++ {
			if unique[j].Impact > unique[i].Impact {
				unique[i], unique[j] = unique[j], unique[i]
			}
		}
	}
	
	return unique
}

// addVisualizationData adds data for graph visualization
func (a *Analyzer) addVisualizationData(path *AttackPath) {
	nodes := []map[string]interface{}{}
	edges := []map[string]interface{}{}
	
	// Add nodes
	nodeSet := make(map[string]bool)
	for _, segment := range path.Path {
		if !nodeSet[segment.From.ID] {
			nodes = append(nodes, map[string]interface{}{
				"id":    segment.From.ID,
				"label": segment.From.Name,
				"type":  segment.From.Type,
				"risk":  segment.From.Risk,
				"compromised": segment.From.Compromised,
			})
			nodeSet[segment.From.ID] = true
		}
		
		if !nodeSet[segment.To.ID] {
			nodes = append(nodes, map[string]interface{}{
				"id":    segment.To.ID,
				"label": segment.To.Name,
				"type":  segment.To.Type,
				"risk":  segment.To.Risk,
				"compromised": segment.To.Compromised,
			})
			nodeSet[segment.To.ID] = true
		}
		
		// Add edge
		edges = append(edges, map[string]interface{}{
			"source": segment.From.ID,
			"target": segment.To.ID,
			"type":   segment.Relationship.Type,
			"risk":   segment.Relationship.Risk,
			"probability": segment.Probability,
		})
	}
	
	path.VisualizationData = map[string]interface{}{
		"nodes": nodes,
		"edges": edges,
		"layout": "hierarchical",
		"style": map[string]interface{}{
			"node_colors": map[string]string{
				"critical": "#d32f2f",
				"high":     "#f57c00",
				"medium":   "#fbc02d",
				"low":      "#388e3c",
			},
			"edge_colors": map[string]string{
				"HAS_VULNERABILITY": "#d32f2f",
				"EXPOSED_TO":       "#f57c00",
				"DEFAULT":          "#757575",
			},
		},
	}
}

// CreateAssetNode creates or updates an asset node in the graph
func (a *Analyzer) CreateAssetNode(ctx context.Context, asset *storage.Asset) error {
	session := a.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	query := `
		MERGE (a:Asset {id: $id})
		SET a.tenant_id = $tenant_id,
			a.type = $type,
			a.name = $name,
			a.value = $value,
			a.criticality = $criticality,
			a.internet_facing = $internet_facing,
			a.last_updated = datetime()
		WITH a
		UNWIND $labels as label
		CALL apoc.create.addLabels(a, [label]) YIELD node
		RETURN node
	`

	_, err := session.Run(ctx, query, map[string]interface{}{
		"id":              asset.ID,
		"tenant_id":       asset.TenantID,
		"type":            asset.Type,
		"name":            asset.Name,
		"value":           asset.Value,
		"criticality":     asset.Criticality,
		"internet_facing": asset.Attributes["internet_facing"],
		"labels":          extractLabels(asset.Labels),
	})

	return err
}

// CreateVulnerabilityNode creates a vulnerability node and links it to an asset
func (a *Analyzer) CreateVulnerabilityNode(ctx context.Context, finding *storage.Finding) error {
	session := a.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	query := `
		MERGE (v:Vulnerability {id: $id})
		SET v.title = $title,
			v.severity = $severity,
			v.cve = $cve,
			v.cvss_score = $cvss_score,
			v.epss_score = $epss_score,
			v.kev = $kev,
			v.last_updated = datetime()
		WITH v
		MATCH (a:Asset {id: $asset_id})
		MERGE (a)-[r:HAS_VULNERABILITY]->(v)
		SET r.discovered_at = $discovered_at,
			r.risk_score = $risk_score
		RETURN v, a, r
	`

	cvssScore := 0.0
	if finding.CVSS != nil {
		cvssScore = finding.CVSS.BaseScore
	}

	epssScore := 0.0
	if finding.EPSS != nil {
		epssScore = finding.EPSS.Probability
	}

	_, err := session.Run(ctx, query, map[string]interface{}{
		"id":            finding.ID,
		"asset_id":      finding.AssetID,
		"title":         finding.Title,
		"severity":      finding.Severity,
		"cve":           strings.Join(finding.CVE, ","),
		"cvss_score":    cvssScore,
		"epss_score":    epssScore,
		"kev":           finding.KEV,
		"discovered_at": finding.DiscoveredAt,
		"risk_score":    finding.RiskScore,
	})

	return err
}

// CreateRelationship creates a relationship between two assets
func (a *Analyzer) CreateRelationship(ctx context.Context, fromID, toID, relType string, properties map[string]interface{}) error {
	session := a.driver.NewSession(ctx, neo4j.SessionConfig{})
	defer session.Close(ctx)

	query := fmt.Sprintf(`
		MATCH (from:Asset {id: $from_id})
		MATCH (to:Asset {id: $to_id})
		MERGE (from)-[r:%s]->(to)
		SET r += $properties,
			r.created_at = CASE WHEN r.created_at IS NULL THEN datetime() ELSE r.created_at END,
			r.updated_at = datetime()
		RETURN r
	`, relType)

	_, err := session.Run(ctx, query, map[string]interface{}{
		"from_id":    fromID,
		"to_id":      toID,
		"properties": properties,
	})

	return err
}

// extractLabels extracts labels for Neo4j from asset labels
func extractLabels(labels map[string]string) []string {
	var result []string
	for key, value := range labels {
		// Create label from key-value pairs
		label := fmt.Sprintf("%s_%s", strings.ToUpper(key), strings.ToUpper(value))
		// Ensure valid Neo4j label format
		label = strings.ReplaceAll(label, "-", "_")
		label = strings.ReplaceAll(label, " ", "_")
		result = append(result, label)
	}
	return result
}