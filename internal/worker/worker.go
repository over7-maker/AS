package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/google/uuid"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sirupsen/logrus"

	"github.com/sovereign-eye/core/internal/messaging"
	"github.com/sovereign-eye/core/internal/storage"
	"github.com/sovereign-eye/core/pkg/scanner"
)

// Worker represents a scanner worker node
type Worker struct {
	id            string
	config        Config
	dockerClient  *client.Client
	storage       storage.Manager
	messageBus    messaging.Bus
	secretsVault  SecretsVault
	logger        *logrus.Logger
	ctx           context.Context
	cancel        context.CancelFunc
}

// Config holds worker configuration
type Config struct {
	WorkerID           string
	MaxConcurrentScans int
	ScanTimeout        time.Duration
	WorkDir            string
	DockerNetwork      string
	RegistryAuth       string
	CosignKeyPath      string
	EnableSBOM         bool
	ResourceLimits     ResourceLimits
}

// ResourceLimits defines container resource limits
type ResourceLimits struct {
	CPUShares          int64
	MemoryLimitMB      int64
	PidsLimit          int64
	ReadonlyRootfs     bool
	NoNewPrivileges    bool
	DropCapabilities   []string
}

// SecretsVault interface for secrets management
type SecretsVault interface {
	GetSecret(ctx context.Context, path string) (map[string]interface{}, error)
	GetDynamicCredentials(ctx context.Context, role string) (map[string]string, error)
}

// ScanTask represents a scanning task
type ScanTask struct {
	ID         string                 `json:"id"`
	WorkflowID string                 `json:"workflow_id"`
	TaskName   string                 `json:"task_name"`
	Tool       string                 `json:"tool"`
	Target     string                 `json:"target"`
	Config     map[string]interface{} `json:"config"`
	Secrets    map[string]string      `json:"secrets"`
	TenantID   string                 `json:"tenant_id"`
}

// ScannerRegistry maintains scanner tool configurations
var ScannerRegistry = map[string]ScannerConfig{
	"amass": {
		Image:   "caffix/amass:v4.2.0",
		Command: []string{"enum"},
		Capabilities: []string{
			"subdomain-discovery",
			"dns-enumeration",
			"certificate-transparency",
		},
	},
	"subfinder": {
		Image:   "projectdiscovery/subfinder:v2.6.3",
		Command: []string{},
		Capabilities: []string{
			"subdomain-discovery",
			"passive-enumeration",
		},
	},
	"naabu": {
		Image:   "projectdiscovery/naabu:v2.2.0",
		Command: []string{},
		Capabilities: []string{
			"port-scanning",
			"service-discovery",
		},
	},
	"nuclei": {
		Image:   "projectdiscovery/nuclei:v3.1.10",
		Command: []string{},
		Capabilities: []string{
			"vulnerability-scanning",
			"cve-detection",
			"misconfiguration-detection",
		},
	},
	"nmap": {
		Image:   "instrumentisto/nmap:7.94",
		Command: []string{},
		Capabilities: []string{
			"port-scanning",
			"service-detection",
			"os-fingerprinting",
		},
	},
}

// ScannerConfig defines scanner tool configuration
type ScannerConfig struct {
	Image        string
	Command      []string
	Capabilities []string
	RequiresCap  []string // Linux capabilities required
}

// New creates a new worker instance
func New(config Config, storage storage.Manager, messageBus messaging.Bus, vault SecretsVault, logger *logrus.Logger) (*Worker, error) {
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	worker := &Worker{
		id:           config.WorkerID,
		config:       config,
		dockerClient: dockerClient,
		storage:      storage,
		messageBus:   messageBus,
		secretsVault: vault,
		logger:       logger,
		ctx:          ctx,
		cancel:       cancel,
	}

	// Create work directory
	if err := os.MkdirAll(config.WorkDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create work directory: %w", err)
	}

	return worker, nil
}

// Start starts the worker
func (w *Worker) Start() error {
	w.logger.WithField("worker_id", w.id).Info("Starting worker")

	// Subscribe to scan tasks
	taskChan, err := w.messageBus.Subscribe("scan-tasks." + w.id)
	if err != nil {
		return fmt.Errorf("failed to subscribe to tasks: %w", err)
	}

	// Process tasks
	go w.processTasks(taskChan)

	// Start health reporting
	go w.reportHealth()

	return nil
}

// Stop stops the worker
func (w *Worker) Stop(ctx context.Context) error {
	w.logger.Info("Stopping worker")
	w.cancel()

	// Wait for running scans to complete or timeout
	done := make(chan struct{})
	go func() {
		// Cleanup logic here
		close(done)
	}()

	select {
	case <-done:
		w.logger.Info("Worker stopped gracefully")
		return nil
	case <-ctx.Done():
		w.logger.Warn("Worker stop timeout")
		return ctx.Err()
	}
}

// processTasks processes incoming scan tasks
func (w *Worker) processTasks(taskChan <-chan messaging.Event) {
	semaphore := make(chan struct{}, w.config.MaxConcurrentScans)

	for {
		select {
		case <-w.ctx.Done():
			return
		case event := <-taskChan:
			var task ScanTask
			if err := json.Unmarshal(event.Data.([]byte), &task); err != nil {
				w.logger.WithError(err).Error("Failed to unmarshal scan task")
				continue
			}

			// Process task concurrently
			semaphore <- struct{}{}
			go func(task ScanTask) {
				defer func() { <-semaphore }()
				w.executeScan(task)
			}(task)
		}
	}
}

// executeScan executes a scanning task
func (w *Worker) executeScan(task ScanTask) {
	startTime := time.Now()
	
	w.logger.WithFields(logrus.Fields{
		"task_id":     task.ID,
		"workflow_id": task.WorkflowID,
		"tool":        task.Tool,
		"target":      task.Target,
	}).Info("Starting scan execution")

	// Get scanner configuration
	scannerConfig, exists := ScannerRegistry[task.Tool]
	if !exists {
		w.reportScanError(task, fmt.Errorf("unknown scanner tool: %s", task.Tool))
		return
	}

	// Verify container image signature
	if w.config.CosignKeyPath != "" {
		if err := w.verifyImageSignature(scannerConfig.Image); err != nil {
			w.reportScanError(task, fmt.Errorf("image signature verification failed: %w", err))
			return
		}
	}

	// Create isolated work directory for this scan
	scanWorkDir := filepath.Join(w.config.WorkDir, task.ID)
	if err := os.MkdirAll(scanWorkDir, 0750); err != nil {
		w.reportScanError(task, fmt.Errorf("failed to create scan work directory: %w", err))
		return
	}
	defer os.RemoveAll(scanWorkDir)

	// Prepare scanner inputs
	inputFile := filepath.Join(scanWorkDir, "input.txt")
	if err := os.WriteFile(inputFile, []byte(task.Target), 0640); err != nil {
		w.reportScanError(task, fmt.Errorf("failed to write input file: %w", err))
		return
	}

	// Build container configuration
	containerConfig := &container.Config{
		Image:        scannerConfig.Image,
		Cmd:          w.buildScannerCommand(task),
		Env:          w.buildEnvironment(task),
		WorkingDir:   "/scan",
		AttachStdout: true,
		AttachStderr: true,
		Tty:          false,
		NetworkMode:  container.NetworkMode(w.config.DockerNetwork),
		Labels: map[string]string{
			"sovereign.task_id":     task.ID,
			"sovereign.workflow_id": task.WorkflowID,
			"sovereign.tenant_id":   task.TenantID,
			"sovereign.tool":        task.Tool,
		},
	}

	// Apply security constraints
	hostConfig := &container.HostConfig{
		AutoRemove: true,
		Mounts: []mount.Mount{
			{
				Type:     mount.TypeBind,
				Source:   scanWorkDir,
				Target:   "/scan",
				ReadOnly: false,
			},
		},
		Resources: container.Resources{
			CPUShares: w.config.ResourceLimits.CPUShares,
			Memory:    w.config.ResourceLimits.MemoryLimitMB * 1024 * 1024,
			PidsLimit: &w.config.ResourceLimits.PidsLimit,
		},
		SecurityOpt: []string{
			"no-new-privileges",
			"apparmor=docker-default",
		},
		ReadonlyRootfs: w.config.ResourceLimits.ReadonlyRootfs,
		CapDrop:        w.config.ResourceLimits.DropCapabilities,
	}

	// Add required capabilities
	if len(scannerConfig.RequiresCap) > 0 {
		hostConfig.CapAdd = scannerConfig.RequiresCap
	}

	// Create container
	ctx, cancel := context.WithTimeout(w.ctx, w.config.ScanTimeout)
	defer cancel()

	resp, err := w.dockerClient.ContainerCreate(
		ctx,
		containerConfig,
		hostConfig,
		nil,
		nil,
		fmt.Sprintf("scan-%s", task.ID),
	)
	if err != nil {
		w.reportScanError(task, fmt.Errorf("failed to create container: %w", err))
		return
	}

	// Start container
	if err := w.dockerClient.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		w.reportScanError(task, fmt.Errorf("failed to start container: %w", err))
		return
	}

	// Capture output
	outputReader, err := w.dockerClient.ContainerLogs(
		ctx,
		resp.ID,
		types.ContainerLogsOptions{
			ShowStdout: true,
			ShowStderr: true,
			Follow:     true,
		},
	)
	if err != nil {
		w.reportScanError(task, fmt.Errorf("failed to get container logs: %w", err))
		return
	}
	defer outputReader.Close()

	output, err := io.ReadAll(outputReader)
	if err != nil {
		w.reportScanError(task, fmt.Errorf("failed to read container output: %w", err))
		return
	}

	// Wait for container to finish
	statusCh, errCh := w.dockerClient.ContainerWait(ctx, resp.ID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			w.reportScanError(task, fmt.Errorf("container wait error: %w", err))
			return
		}
	case status := <-statusCh:
		if status.StatusCode != 0 {
			w.reportScanError(task, fmt.Errorf("scanner exited with code %d: %s", status.StatusCode, string(output)))
			return
		}
	case <-ctx.Done():
		w.reportScanError(task, fmt.Errorf("scan timeout exceeded"))
		return
	}

	// Parse scanner output
	scanResult, err := scanner.ParseOutput(task.Tool, output)
	if err != nil {
		w.reportScanError(task, fmt.Errorf("failed to parse scanner output: %w", err))
		return
	}

	// Generate SBOM if enabled
	if w.config.EnableSBOM {
		sbom, err := w.generateSBOM(resp.ID)
		if err != nil {
			w.logger.WithError(err).Warn("Failed to generate SBOM")
		} else {
			scanResult.SBOM = sbom
		}
	}

	// Report successful scan
	w.reportScanSuccess(task, scanResult, time.Since(startTime))
}

// verifyImageSignature verifies container image signature using Cosign
func (w *Worker) verifyImageSignature(image string) error {
	cmd := exec.Command("cosign", "verify", "--key", w.config.CosignKeyPath, image)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cosign verification failed: %s", string(output))
	}
	
	w.logger.WithField("image", image).Debug("Image signature verified successfully")
	return nil
}

// buildScannerCommand builds the scanner command with parameters
func (w *Worker) buildScannerCommand(task ScanTask) []string {
	baseCmd := ScannerRegistry[task.Tool].Command
	cmd := make([]string, len(baseCmd))
	copy(cmd, baseCmd)

	// Add tool-specific parameters based on config
	switch task.Tool {
	case "amass":
		if passive, ok := task.Config["passive"].(bool); ok && passive {
			cmd = append(cmd, "-passive")
		}
		cmd = append(cmd, "-d", task.Target)
		
	case "nuclei":
		if templates, ok := task.Config["templates"].([]string); ok {
			for _, template := range templates {
				cmd = append(cmd, "-t", template)
			}
		}
		if severity, ok := task.Config["severity"].([]string); ok {
			cmd = append(cmd, "-severity", strings.Join(severity, ","))
		}
		cmd = append(cmd, "-target", "/scan/input.txt")
		
	case "naabu":
		if ports, ok := task.Config["ports"].(string); ok {
			cmd = append(cmd, "-p", ports)
		}
		if rate, ok := task.Config["rate"].(int); ok {
			cmd = append(cmd, "-rate", fmt.Sprintf("%d", rate))
		}
		cmd = append(cmd, "-host", task.Target)
	}

	return cmd
}

// buildEnvironment builds environment variables for the scanner
func (w *Worker) buildEnvironment(task ScanTask) []string {
	env := []string{
		"SCAN_ID=" + task.ID,
		"WORKFLOW_ID=" + task.WorkflowID,
		"TENANT_ID=" + task.TenantID,
	}

	// Add secrets as environment variables
	for key, value := range task.Secrets {
		env = append(env, fmt.Sprintf("%s=%s", strings.ToUpper(key), value))
	}

	return env
}

// generateSBOM generates Software Bill of Materials for the scan
func (w *Worker) generateSBOM(containerID string) (map[string]interface{}, error) {
	// Implementation would use Syft or similar tool
	// This is a placeholder
	return map[string]interface{}{
		"format":    "spdx",
		"version":   "2.3",
		"createdAt": time.Now().UTC(),
		"tool":      "syft",
	}, nil
}

// reportScanSuccess reports successful scan completion
func (w *Worker) reportScanSuccess(task ScanTask, result *scanner.Result, duration time.Duration) {
	// Store raw output in Elasticsearch
	if err := w.storage.StoreScanOutput(task.ID, result.RawOutput); err != nil {
		w.logger.WithError(err).Error("Failed to store scan output")
	}

	// Store structured results in PostgreSQL
	scanResult := &storage.ScanResult{
		ID:         task.ID,
		WorkflowID: task.WorkflowID,
		TaskName:   task.TaskName,
		Tool:       task.Tool,
		Target:     task.Target,
		Status:     "completed",
		Output:     result.Structured,
		Findings:   result.FindingIDs,
		StartTime:  time.Now().Add(-duration),
		EndTime:    time.Now(),
		Duration:   duration,
	}

	if err := w.storage.SaveScanResult(scanResult); err != nil {
		w.logger.WithError(err).Error("Failed to save scan result")
	}

	// Publish completion event
	event := &messaging.Event{
		Type:   "scan.completed",
		Source: "worker." + w.id,
		Data: map[string]interface{}{
			"task_id":     task.ID,
			"workflow_id": task.WorkflowID,
			"tool":        task.Tool,
			"target":      task.Target,
			"duration":    duration.Seconds(),
			"findings":    len(result.FindingIDs),
		},
		Timestamp: time.Now(),
	}

	if err := w.messageBus.Publish("scan-results", event); err != nil {
		w.logger.WithError(err).Error("Failed to publish scan completion event")
	}

	w.logger.WithFields(logrus.Fields{
		"task_id":  task.ID,
		"duration": duration,
		"findings": len(result.FindingIDs),
	}).Info("Scan completed successfully")
}

// reportScanError reports scan failure
func (w *Worker) reportScanError(task ScanTask, err error) {
	w.logger.WithFields(logrus.Fields{
		"task_id": task.ID,
		"tool":    task.Tool,
		"target":  task.Target,
		"error":   err.Error(),
	}).Error("Scan failed")

	// Store error in database
	scanResult := &storage.ScanResult{
		ID:         task.ID,
		WorkflowID: task.WorkflowID,
		TaskName:   task.TaskName,
		Tool:       task.Tool,
		Target:     task.Target,
		Status:     "failed",
		Error:      err.Error(),
		StartTime:  time.Now(),
		EndTime:    time.Now(),
	}

	if err := w.storage.SaveScanResult(scanResult); err != nil {
		w.logger.WithError(err).Error("Failed to save scan error")
	}

	// Publish failure event
	event := &messaging.Event{
		Type:   "scan.failed",
		Source: "worker." + w.id,
		Data: map[string]interface{}{
			"task_id":     task.ID,
			"workflow_id": task.WorkflowID,
			"tool":        task.Tool,
			"target":      task.Target,
			"error":       err.Error(),
		},
		Timestamp: time.Now(),
	}

	if err := w.messageBus.Publish("scan-results", event); err != nil {
		w.logger.WithError(err).Error("Failed to publish scan failure event")
	}
}

// reportHealth periodically reports worker health
func (w *Worker) reportHealth() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			health := map[string]interface{}{
				"worker_id": w.id,
				"status":    "healthy",
				"timestamp": time.Now().Unix(),
				"metrics": map[string]interface{}{
					"cpu_usage":    w.getCPUUsage(),
					"memory_usage": w.getMemoryUsage(),
					"active_scans": w.getActiveScanCount(),
				},
			}

			event := &messaging.Event{
				Type:      "worker.health",
				Source:    "worker." + w.id,
				Data:      health,
				Timestamp: time.Now(),
			}

			if err := w.messageBus.Publish("worker-health", event); err != nil {
				w.logger.WithError(err).Error("Failed to report health")
			}
		}
	}
}

// Helper methods for metrics
func (w *Worker) getCPUUsage() float64 {
	// Implementation would read from /proc/stat or use a library
	return 0.0
}

func (w *Worker) getMemoryUsage() float64 {
	// Implementation would read from /proc/meminfo or use a library
	return 0.0
}

func (w *Worker) getActiveScanCount() int {
	// Implementation would track active scans
	return 0
}