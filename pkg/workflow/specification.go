package workflow

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/xeipuuv/gojsonschema"
	"gopkg.in/yaml.v3"
)

// Specification represents a workflow specification in YAML format
type Specification struct {
	APIVersion  string            `yaml:"apiVersion" json:"apiVersion"`
	Kind        string            `yaml:"kind" json:"kind"`
	Metadata    Metadata          `yaml:"metadata" json:"metadata"`
	Spec        WorkflowSpec      `yaml:"spec" json:"spec"`
	Status      *WorkflowStatus   `yaml:"status,omitempty" json:"status,omitempty"`
}

// Metadata contains workflow metadata
type Metadata struct {
	Name        string            `yaml:"name" json:"name"`
	Namespace   string            `yaml:"namespace" json:"namespace"`
	Labels      map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
	Annotations map[string]string `yaml:"annotations,omitempty" json:"annotations,omitempty"`
	TenantID    string            `yaml:"tenantId" json:"tenantId"`
	CreatedAt   time.Time         `yaml:"createdAt" json:"createdAt"`
	UpdatedAt   time.Time         `yaml:"updatedAt" json:"updatedAt"`
}

// WorkflowSpec defines the workflow specification
type WorkflowSpec struct {
	Description     string                 `yaml:"description,omitempty" json:"description,omitempty"`
	Schedule        *Schedule              `yaml:"schedule,omitempty" json:"schedule,omitempty"`
	Targets         []Target               `yaml:"targets" json:"targets"`
	Tasks           []Task                 `yaml:"tasks" json:"tasks"`
	Parameters      map[string]Parameter   `yaml:"parameters,omitempty" json:"parameters,omitempty"`
	Secrets         []SecretRef            `yaml:"secrets,omitempty" json:"secrets,omitempty"`
	RateLimits      *RateLimits           `yaml:"rateLimits,omitempty" json:"rateLimits,omitempty"`
	Notifications   []Notification        `yaml:"notifications,omitempty" json:"notifications,omitempty"`
	Timeout         string                `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	MaxRetries      int                   `yaml:"maxRetries,omitempty" json:"maxRetries,omitempty"`
	OnFailure       string                `yaml:"onFailure,omitempty" json:"onFailure,omitempty"`
}

// Schedule defines workflow scheduling
type Schedule struct {
	Cron     string `yaml:"cron,omitempty" json:"cron,omitempty"`
	Interval string `yaml:"interval,omitempty" json:"interval,omitempty"`
	Timezone string `yaml:"timezone,omitempty" json:"timezone,omitempty"`
}

// Target represents a scan target
type Target struct {
	Type       string            `yaml:"type" json:"type"` // domain, ip, cidr, asn
	Value      string            `yaml:"value" json:"value"`
	Labels     map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
	Excluded   bool              `yaml:"excluded,omitempty" json:"excluded,omitempty"`
	Criticality string           `yaml:"criticality,omitempty" json:"criticality,omitempty"` // low, medium, high, critical
}

// Task represents a workflow task
type Task struct {
	Name         string              `yaml:"name" json:"name"`
	Type         string              `yaml:"type" json:"type"` // scan, analyze, remediate, notify
	Tool         string              `yaml:"tool,omitempty" json:"tool,omitempty"`
	Config       map[string]interface{} `yaml:"config,omitempty" json:"config,omitempty"`
	Inputs       []Input             `yaml:"inputs,omitempty" json:"inputs,omitempty"`
	Outputs      []Output            `yaml:"outputs,omitempty" json:"outputs,omitempty"`
	DependsOn    []string            `yaml:"dependsOn,omitempty" json:"dependsOn,omitempty"`
	Condition    string              `yaml:"condition,omitempty" json:"condition,omitempty"`
	Approval     *ApprovalConfig     `yaml:"approval,omitempty" json:"approval,omitempty"`
	Timeout      string              `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	Retries      int                 `yaml:"retries,omitempty" json:"retries,omitempty"`
	Parallelism  int                 `yaml:"parallelism,omitempty" json:"parallelism,omitempty"`
	FanOut       *FanOutConfig       `yaml:"fanOut,omitempty" json:"fanOut,omitempty"`
}

// Input defines task input
type Input struct {
	Name     string `yaml:"name" json:"name"`
	Source   string `yaml:"source" json:"source"` // parameter, task, static
	Value    string `yaml:"value,omitempty" json:"value,omitempty"`
	JSONPath string `yaml:"jsonPath,omitempty" json:"jsonPath,omitempty"`
}

// Output defines task output
type Output struct {
	Name   string `yaml:"name" json:"name"`
	Target string `yaml:"target,omitempty" json:"target,omitempty"`
}

// ApprovalConfig defines approval requirements
type ApprovalConfig struct {
	Required    bool     `yaml:"required" json:"required"`
	Role        string   `yaml:"role,omitempty" json:"role,omitempty"`
	Approvers   []string `yaml:"approvers,omitempty" json:"approvers,omitempty"`
	Timeout     string   `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	Description string   `yaml:"description,omitempty" json:"description,omitempty"`
}

// FanOutConfig defines dynamic fan-out configuration
type FanOutConfig struct {
	Over     string `yaml:"over" json:"over"` // JSONPath to array
	Template Task   `yaml:"template" json:"template"`
	MaxConcurrency int `yaml:"maxConcurrency,omitempty" json:"maxConcurrency,omitempty"`
}

// Parameter defines workflow parameter
type Parameter struct {
	Type        string      `yaml:"type" json:"type"` // string, number, boolean, array, object
	Default     interface{} `yaml:"default,omitempty" json:"default,omitempty"`
	Required    bool        `yaml:"required,omitempty" json:"required,omitempty"`
	Description string      `yaml:"description,omitempty" json:"description,omitempty"`
	Validation  string      `yaml:"validation,omitempty" json:"validation,omitempty"` // regex or JSONSchema
}

// SecretRef references a secret in Vault
type SecretRef struct {
	Name     string `yaml:"name" json:"name"`
	Path     string `yaml:"path" json:"path"`
	Key      string `yaml:"key,omitempty" json:"key,omitempty"`
	Version  string `yaml:"version,omitempty" json:"version,omitempty"`
}

// RateLimits defines rate limiting configuration
type RateLimits struct {
	PerTarget  int `yaml:"perTarget,omitempty" json:"perTarget,omitempty"`
	PerASN     int `yaml:"perASN,omitempty" json:"perASN,omitempty"`
	PerWorkflow int `yaml:"perWorkflow,omitempty" json:"perWorkflow,omitempty"`
	Global     int `yaml:"global,omitempty" json:"global,omitempty"`
}

// Notification defines notification configuration
type Notification struct {
	Type      string            `yaml:"type" json:"type"` // email, slack, webhook
	Condition string            `yaml:"condition" json:"condition"` // always, on_failure, on_success
	Config    map[string]string `yaml:"config" json:"config"`
}

// WorkflowStatus represents the current status of a workflow
type WorkflowStatus struct {
	Phase          string              `yaml:"phase" json:"phase"` // pending, running, succeeded, failed, cancelled
	StartTime      *time.Time          `yaml:"startTime,omitempty" json:"startTime,omitempty"`
	CompletionTime *time.Time          `yaml:"completionTime,omitempty" json:"completionTime,omitempty"`
	Tasks          map[string]TaskStatus `yaml:"tasks,omitempty" json:"tasks,omitempty"`
	Message        string              `yaml:"message,omitempty" json:"message,omitempty"`
	Progress       int                 `yaml:"progress,omitempty" json:"progress,omitempty"`
}

// TaskStatus represents the status of a single task
type TaskStatus struct {
	Phase          string     `yaml:"phase" json:"phase"`
	StartTime      *time.Time `yaml:"startTime,omitempty" json:"startTime,omitempty"`
	CompletionTime *time.Time `yaml:"completionTime,omitempty" json:"completionTime,omitempty"`
	Outputs        map[string]interface{} `yaml:"outputs,omitempty" json:"outputs,omitempty"`
	Error          string     `yaml:"error,omitempty" json:"error,omitempty"`
	Retries        int        `yaml:"retries,omitempty" json:"retries,omitempty"`
}

// WorkflowSchema is the JSON Schema for workflow validation
const WorkflowSchema = `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Sovereign Eye Workflow Specification",
  "type": "object",
  "required": ["apiVersion", "kind", "metadata", "spec"],
  "properties": {
    "apiVersion": {
      "type": "string",
      "enum": ["sovereign.eye/v1"]
    },
    "kind": {
      "type": "string",
      "enum": ["Workflow"]
    },
    "metadata": {
      "type": "object",
      "required": ["name", "namespace", "tenantId"],
      "properties": {
        "name": {
          "type": "string",
          "pattern": "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"
        },
        "namespace": {
          "type": "string"
        },
        "tenantId": {
          "type": "string",
          "format": "uuid"
        },
        "labels": {
          "type": "object",
          "additionalProperties": {
            "type": "string"
          }
        },
        "annotations": {
          "type": "object",
          "additionalProperties": {
            "type": "string"
          }
        }
      }
    },
    "spec": {
      "type": "object",
      "required": ["targets", "tasks"],
      "properties": {
        "targets": {
          "type": "array",
          "minItems": 1,
          "items": {
            "type": "object",
            "required": ["type", "value"],
            "properties": {
              "type": {
                "type": "string",
                "enum": ["domain", "ip", "cidr", "asn"]
              },
              "value": {
                "type": "string"
              },
              "criticality": {
                "type": "string",
                "enum": ["low", "medium", "high", "critical"]
              }
            }
          }
        },
        "tasks": {
          "type": "array",
          "minItems": 1,
          "items": {
            "type": "object",
            "required": ["name", "type"],
            "properties": {
              "name": {
                "type": "string",
                "pattern": "^[a-zA-Z0-9-_]+$"
              },
              "type": {
                "type": "string",
                "enum": ["scan", "analyze", "remediate", "notify"]
              },
              "tool": {
                "type": "string"
              },
              "approval": {
                "type": "object",
                "properties": {
                  "required": {
                    "type": "boolean"
                  },
                  "role": {
                    "type": "string"
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}`

// Validate validates a workflow specification against the schema
func (s *Specification) Validate() error {
	schemaLoader := gojsonschema.NewStringLoader(WorkflowSchema)
	
	specJSON, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("failed to marshal specification: %w", err)
	}
	
	documentLoader := gojsonschema.NewBytesLoader(specJSON)
	
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return fmt.Errorf("schema validation error: %w", err)
	}
	
	if !result.Valid() {
		var errors []string
		for _, desc := range result.Errors() {
			errors = append(errors, desc.String())
		}
		return fmt.Errorf("validation failed: %v", errors)
	}
	
	return nil
}

// ParseSpecification parses a YAML workflow specification
func ParseSpecification(data []byte) (*Specification, error) {
	var spec Specification
	
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}
	
	// Set defaults
	if spec.Metadata.CreatedAt.IsZero() {
		spec.Metadata.CreatedAt = time.Now()
	}
	spec.Metadata.UpdatedAt = time.Now()
	
	// Validate against schema
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	
	return &spec, nil
}

// GenerateID generates a unique workflow ID
func GenerateID() string {
	return uuid.New().String()
}