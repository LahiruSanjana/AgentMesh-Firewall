package policy

import (
	"agentmesh/pkg/mcp"
	"context"
	"time"
)

type Decision struct {
	Allow              bool          `json:"allow"`
	Reason             string        `json:"reason"`
	Violations         []string      `json:"violations"`
	Action             string        `json:"action,omitempty"`
	Retryable          bool          `json:"retryable"`
	EvaluationDuration time.Duration `json:"evaluation_duration"`
}

type Engine interface {
	Evaluate(ctx context.Context, input *mcp.PolicyInput) (*Decision, error)
}
