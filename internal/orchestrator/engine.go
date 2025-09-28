package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"

	"github.com/sovereign-eye/core/internal/messaging"
	"github.com/sovereign-eye/core/internal/storage"
	"github.com/sovereign-eye/core/pkg/workflow"
)

// Engine is the main orchestration engine
type Engine struct {
	config         Config
	storage        storage.Manager
	messageBus     messaging.Bus
	logger         *logrus.Logger
	
	// Workflow management
	workflows      map[string]*WorkflowInstance
	workflowMutex  sync.RWMutex
	
	// Worker pool
	workerPool     *WorkerPool
	taskQueue      chan *TaskExecution
	
	// Rate limiting
	tenantLimiters map[string]*rate.Limiter
	targetLimiters map[string]*rate.Limiter
	asnLimiters    map[string]*rate.Limiter
	limiterMutex   sync.RWMutex
	
	// Lifecycle
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
}

// Config holds orchestrator configuration
type Config struct {
	Workers            int
	EnableApprovals    bool
	MaxConcurrency     int
	TaskTimeout        time.Duration
	RetryAttempts      int
	RetryDelay         time.Duration
	RateLimitPerTenant int
	RateLimitPerTarget int
	RateLimitPerASN    int
}

// WorkflowInstance represents a running workflow
type WorkflowInstance struct {
	ID              string
	Specification   *workflow.Specification
	State           WorkflowState
	StartTime       time.Time
	EndTime         *time.Time
	TaskStates      map[string]*TaskState
	Parameters      map[string]interface{}
	Secrets         map[string]string
	Context         context.Context
	Cancel          context.CancelFunc
	mutex           sync.RWMutex
}

// WorkflowState represents the state of a workflow
type WorkflowState string

const (
	WorkflowStatePending    WorkflowState = "pending"
	WorkflowStateRunning    WorkflowState = "running"
	WorkflowStateWaiting    WorkflowState = "waiting_approval"
	WorkflowStateSucceeded  WorkflowState = "succeeded"
	WorkflowStateFailed     WorkflowState = "failed"
	WorkflowStateCancelled  WorkflowState = "cancelled"
)

// TaskState represents the state of a task
type TaskState struct {
	Name           string
	State          TaskExecutionState
	StartTime      *time.Time
	EndTime        *time.Time
	Outputs        map[string]interface{}
	Error          error
	RetryCount     int
	ApprovalStatus *ApprovalStatus
}

// TaskExecutionState represents task execution state
type TaskExecutionState string

const (
	TaskStatePending         TaskExecutionState = "pending"
	TaskStateRunning         TaskExecutionState = "running"
	TaskStateWaitingApproval TaskExecutionState = "waiting_approval"
	TaskStateSucceeded       TaskExecutionState = "succeeded"
	TaskStateFailed          TaskExecutionState = "failed"
	TaskStateSkipped         TaskExecutionState = "skipped"
	TaskStateCancelled       TaskExecutionState = "cancelled"
)

// TaskExecution represents a task to be executed
type TaskExecution struct {
	WorkflowID   string
	Task         workflow.Task
	Inputs       map[string]interface{}
	Context      context.Context
	RetryCount   int
	FanOutIndex  int
}

// ApprovalStatus represents the approval status of a task
type ApprovalStatus struct {
	Required     bool
	RequestTime  time.Time
	ApprovedBy   string
	ApprovedAt   *time.Time
	RejectedBy   string
	RejectedAt   *time.Time
	Comment      string
}

// New creates a new orchestrator engine
func New(config Config, storage storage.Manager, messageBus messaging.Bus, logger *logrus.Logger) (*Engine, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	engine := &Engine{
		config:         config,
		storage:        storage,
		messageBus:     messageBus,
		logger:         logger,
		workflows:      make(map[string]*WorkflowInstance),
		taskQueue:      make(chan *TaskExecution, config.Workers * 10),
		tenantLimiters: make(map[string]*rate.Limiter),
		targetLimiters: make(map[string]*rate.Limiter),
		asnLimiters:    make(map[string]*rate.Limiter),
		ctx:            ctx,
		cancel:         cancel,
	}
	
	// Initialize worker pool
	engine.workerPool = NewWorkerPool(config.Workers, engine.executeTask)
	
	return engine, nil
}

// Start starts the orchestrator engine
func (e *Engine) Start(ctx context.Context) error {
	e.logger.Info("Starting orchestrator engine")
	
	// Start worker pool
	e.workerPool.Start()
	
	// Start workflow processor
	e.wg.Add(1)
	go e.processWorkflows()
	
	// Start task dispatcher
	e.wg.Add(1)
	go e.dispatchTasks()
	
	// Subscribe to workflow events
	if err := e.subscribeToEvents(); err != nil {
		return fmt.Errorf("failed to subscribe to events: %w", err)
	}
	
	// Load pending workflows from storage
	if err := e.loadPendingWorkflows(); err != nil {
		return fmt.Errorf("failed to load pending workflows: %w", err)
	}
	
	e.logger.Info("Orchestrator engine started successfully")
	return nil
}

// Stop stops the orchestrator engine
func (e *Engine) Stop(ctx context.Context) error {
	e.logger.Info("Stopping orchestrator engine")
	
	// Cancel context
	e.cancel()
	
	// Stop accepting new workflows
	close(e.taskQueue)
	
	// Wait for workers to finish
	e.workerPool.Stop()
	
	// Wait for goroutines
	done := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		e.logger.Info("Orchestrator engine stopped gracefully")
		return nil
	case <-ctx.Done():
		e.logger.Warn("Orchestrator engine stop timeout")
		return ctx.Err()
	}
}

// ExecuteWorkflow executes a workflow specification
func (e *Engine) ExecuteWorkflow(spec *workflow.Specification, parameters map[string]interface{}) (string, error) {
	// Validate specification
	if err := spec.Validate(); err != nil {
		return "", fmt.Errorf("invalid workflow specification: %w", err)
	}
	
	// Check tenant rate limit
	if !e.checkTenantRateLimit(spec.Metadata.TenantID) {
		return "", fmt.Errorf("tenant rate limit exceeded")
	}
	
	// Create workflow instance
	instanceID := uuid.New().String()
	ctx, cancel := context.WithCancel(e.ctx)
	
	instance := &WorkflowInstance{
		ID:            instanceID,
		Specification: spec,
		State:         WorkflowStatePending,
		StartTime:     time.Now(),
		TaskStates:    make(map[string]*TaskState),
		Parameters:    parameters,
		Secrets:       make(map[string]string),
		Context:       ctx,
		Cancel:        cancel,
	}
	
	// Initialize task states
	for _, task := range spec.Spec.Tasks {
		instance.TaskStates[task.Name] = &TaskState{
			Name:  task.Name,
			State: TaskStatePending,
		}
	}
	
	// Store workflow
	e.workflowMutex.Lock()
	e.workflows[instanceID] = instance
	e.workflowMutex.Unlock()
	
	// Persist to storage
	if err := e.storage.SaveWorkflow(instance); err != nil {
		return "", fmt.Errorf("failed to save workflow: %w", err)
	}
	
	// Publish workflow created event
	event := &messaging.Event{
		Type:      "workflow.created",
		Source:    "orchestrator",
		Data:      map[string]interface{}{"workflow_id": instanceID},
		Timestamp: time.Now(),
	}
	if err := e.messageBus.Publish("workflows", event); err != nil {
		e.logger.WithError(err).Error("Failed to publish workflow created event")
	}
	
	e.logger.WithFields(logrus.Fields{
		"workflow_id": instanceID,
		"name":        spec.Metadata.Name,
		"tenant_id":   spec.Metadata.TenantID,
	}).Info("Workflow execution started")
	
	return instanceID, nil
}

// processWorkflows processes workflow state changes
func (e *Engine) processWorkflows() {
	defer e.wg.Done()
	
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			e.processWorkflowStates()
		}
	}
}

// processWorkflowStates processes the state of all active workflows
func (e *Engine) processWorkflowStates() {
	e.workflowMutex.RLock()
	workflows := make([]*WorkflowInstance, 0, len(e.workflows))
	for _, w := range e.workflows {
		workflows = append(workflows, w)
	}
	e.workflowMutex.RUnlock()
	
	for _, workflow := range workflows {
		workflow.mutex.Lock()
		
		switch workflow.State {
		case WorkflowStatePending:
			// Start workflow
			workflow.State = WorkflowStateRunning
			e.scheduleInitialTasks(workflow)
			
		case WorkflowStateRunning:
			// Check if all tasks are complete
			if e.areAllTasksComplete(workflow) {
				if e.hasFailedTasks(workflow) {
					workflow.State = WorkflowStateFailed
				} else {
					workflow.State = WorkflowStateSucceeded
				}
				endTime := time.Now()
				workflow.EndTime = &endTime
				e.finalizeWorkflow(workflow)
			} else {
				// Schedule ready tasks
				e.scheduleReadyTasks(workflow)
			}
			
		case WorkflowStateWaiting:
			// Check for approvals
			e.checkApprovals(workflow)
		}
		
		workflow.mutex.Unlock()
		
		// Update storage
		if err := e.storage.UpdateWorkflow(workflow); err != nil {
			e.logger.WithError(err).Error("Failed to update workflow state")
		}
	}
}

// scheduleInitialTasks schedules tasks with no dependencies
func (e *Engine) scheduleInitialTasks(workflow *WorkflowInstance) {
	for _, task := range workflow.Specification.Spec.Tasks {
		if len(task.DependsOn) == 0 {
			e.scheduleTask(workflow, task)
		}
	}
}

// scheduleReadyTasks schedules tasks whose dependencies are satisfied
func (e *Engine) scheduleReadyTasks(workflow *WorkflowInstance) {
	for _, task := range workflow.Specification.Spec.Tasks {
		taskState := workflow.TaskStates[task.Name]
		
		// Skip if not pending
		if taskState.State != TaskStatePending {
			continue
		}
		
		// Check if dependencies are satisfied
		if e.areDependenciesSatisfied(workflow, task) {
			// Check condition
			if task.Condition != "" && !e.evaluateCondition(workflow, task.Condition) {
				taskState.State = TaskStateSkipped
				continue
			}
			
			// Check for approval requirement
			if task.Approval != nil && task.Approval.Required {
				taskState.State = TaskStateWaitingApproval
				taskState.ApprovalStatus = &ApprovalStatus{
					Required:    true,
					RequestTime: time.Now(),
				}
				e.requestApproval(workflow, task)
				continue
			}
			
			// Schedule task
			e.scheduleTask(workflow, task)
		}
	}
}

// scheduleTask schedules a task for execution
func (e *Engine) scheduleTask(workflow *WorkflowInstance, task workflow.Task) {
	taskState := workflow.TaskStates[task.Name]
	taskState.State = TaskStateRunning
	startTime := time.Now()
	taskState.StartTime = &startTime
	
	// Handle fan-out
	if task.FanOut != nil {
		e.scheduleFanOutTasks(workflow, task)
	} else {
		// Prepare inputs
		inputs, err := e.prepareTaskInputs(workflow, task)
		if err != nil {
			e.logger.WithError(err).Error("Failed to prepare task inputs")
			taskState.State = TaskStateFailed
			taskState.Error = err
			return
		}
		
		// Create task execution
		execution := &TaskExecution{
			WorkflowID: workflow.ID,
			Task:       task,
			Inputs:     inputs,
			Context:    workflow.Context,
			RetryCount: 0,
		}
		
		// Queue task
		select {
		case e.taskQueue <- execution:
			e.logger.WithFields(logrus.Fields{
				"workflow_id": workflow.ID,
				"task":        task.Name,
			}).Debug("Task queued for execution")
		case <-workflow.Context.Done():
			taskState.State = TaskStateCancelled
		}
	}
}

// executeTask executes a single task
func (e *Engine) executeTask(execution *TaskExecution) {
	e.workflowMutex.RLock()
	workflow, exists := e.workflows[execution.WorkflowID]
	e.workflowMutex.RUnlock()
	
	if !exists {
		e.logger.Error("Workflow not found for task execution")
		return
	}
	
	workflow.mutex.Lock()
	taskState := workflow.TaskStates[execution.Task.Name]
	workflow.mutex.Unlock()
	
	// Check rate limits
	if !e.checkRateLimits(workflow, execution.Task) {
		// Requeue task
		time.Sleep(time.Second)
		e.taskQueue <- execution
		return
	}
	
	// Execute task based on type
	var outputs map[string]interface{}
	var err error
	
	switch execution.Task.Type {
	case "scan":
		outputs, err = e.executeScanTask(workflow, execution)
	case "analyze":
		outputs, err = e.executeAnalyzeTask(workflow, execution)
	case "remediate":
		outputs, err = e.executeRemediateTask(workflow, execution)
	case "notify":
		outputs, err = e.executeNotifyTask(workflow, execution)
	default:
		err = fmt.Errorf("unknown task type: %s", execution.Task.Type)
	}
	
	// Update task state
	workflow.mutex.Lock()
	defer workflow.mutex.Unlock()
	
	if err != nil {
		taskState.Error = err
		execution.RetryCount++
		
		if execution.RetryCount < e.config.RetryAttempts {
			// Retry task
			e.logger.WithFields(logrus.Fields{
				"workflow_id": workflow.ID,
				"task":        execution.Task.Name,
				"retry":       execution.RetryCount,
			}).Warn("Task failed, retrying")
			
			time.Sleep(e.config.RetryDelay)
			e.taskQueue <- execution
		} else {
			// Mark as failed
			taskState.State = TaskStateFailed
			endTime := time.Now()
			taskState.EndTime = &endTime
			
			e.logger.WithFields(logrus.Fields{
				"workflow_id": workflow.ID,
				"task":        execution.Task.Name,
				"error":       err.Error(),
			}).Error("Task failed after retries")
		}
	} else {
		// Task succeeded
		taskState.State = TaskStateSucceeded
		taskState.Outputs = outputs
		endTime := time.Now()
		taskState.EndTime = &endTime
		
		e.logger.WithFields(logrus.Fields{
			"workflow_id": workflow.ID,
			"task":        execution.Task.Name,
		}).Info("Task completed successfully")
	}
	
	// Publish task completion event
	event := &messaging.Event{
		Type:   "task.completed",
		Source: "orchestrator",
		Data: map[string]interface{}{
			"workflow_id": workflow.ID,
			"task":        execution.Task.Name,
			"state":       taskState.State,
		},
		Timestamp: time.Now(),
	}
	e.messageBus.Publish("tasks", event)
}

// Helper methods...

func (e *Engine) checkTenantRateLimit(tenantID string) bool {
	e.limiterMutex.Lock()
	defer e.limiterMutex.Unlock()
	
	limiter, exists := e.tenantLimiters[tenantID]
	if !exists {
		limiter = rate.NewLimiter(rate.Limit(e.config.RateLimitPerTenant), e.config.RateLimitPerTenant)
		e.tenantLimiters[tenantID] = limiter
	}
	
	return limiter.Allow()
}

func (e *Engine) areDependenciesSatisfied(workflow *WorkflowInstance, task workflow.Task) bool {
	for _, dep := range task.DependsOn {
		depState := workflow.TaskStates[dep]
		if depState == nil || depState.State != TaskStateSucceeded {
			return false
		}
	}
	return true
}

func (e *Engine) areAllTasksComplete(workflow *WorkflowInstance) bool {
	for _, state := range workflow.TaskStates {
		if state.State == TaskStatePending || state.State == TaskStateRunning || state.State == TaskStateWaitingApproval {
			return false
		}
	}
	return true
}

func (e *Engine) hasFailedTasks(workflow *WorkflowInstance) bool {
	for _, state := range workflow.TaskStates {
		if state.State == TaskStateFailed {
			return true
		}
	}
	return false
}

// Additional helper methods would be implemented here...