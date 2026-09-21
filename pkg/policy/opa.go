package policy

import (
	"agentmesh/pkg/mcp"
	"context"
	"encoding/json"
	"fmt"
	"github.com/open-policy-agent/opa/rego"
	"time"
)

type OPAEngine struct {
	query rego.PreparedEvalQuery
}

func NewOPAEngine(ctx context.Context, policyCode string, queryPath string) (*OPAEngine, error) {
	prepared, err := rego.New(
		rego.Query(queryPath),
		rego.Module("policy.rego", policyCode),
	).PrepareForEval(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed to prepare OPA query: %w", err)
	}

	return &OPAEngine{
		query: prepared,
	}, nil
}

func (e *OPAEngine) Evaluate(ctx context.Context, input *mcp.PolicyInput) (*Decision, error) {
	start := time.Now()

	regoInput, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal input: %w", err)
	}

	regoInputMap := map[string]any{}
	if err := json.Unmarshal(regoInput, &regoInputMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal input to map: %w", err)
	}

	result, err := e.query.Eval(ctx, rego.EvalInput(regoInputMap))
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate OPA query: %w", err)
	}

	if len(result) == 0 || len(result[0].Expressions) == 0 {
		return &Decision{
			Allow:              false,
			Reason:             "no policy decision returned",
			EvaluationDuration: time.Since(start),
		}, nil
	}

	decision, ok := result[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected decision format: %v", result[0].Expressions[0].Value)
	}

	allow, _ := decision["allow"].(bool)
	reason, _ := decision["reason"].(string)

	var violations []string
	if rawViolations, ok := decision["violations"].([]interface{}); ok {
		for _, v := range rawViolations {
			if str, ok := v.(string); ok {
				violations = append(violations, str)
			}
		}
	}

	return &Decision{
		Allow:              allow,
		Reason:             reason,
		Violations:         violations,
		EvaluationDuration: time.Since(start),
	}, nil

}