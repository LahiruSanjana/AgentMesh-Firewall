package policy

import (
	"context"
	"time"
	"agentmesh/pkg/mcp"
)

type Decision struct {
	Allow              bool          `json:"allow"`
	Reason             string        `json:"reason"`
	Violations         []string      `json:"violations"`
	EvaluationDuration time.Duration `json:"evaluation_duration"` 
}

type Engine interface {
	Evaluate(ctx context.Context, input *mcp.PolicyInput) (*Decision, error)
}