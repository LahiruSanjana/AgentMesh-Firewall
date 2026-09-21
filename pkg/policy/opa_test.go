package policy

import (
	"agentmesh/pkg/auth"
	"agentmesh/pkg/mcp"
	"context"
	"testing"
	"time"
	"encoding/json"
)

const samplePolicy = `
      package agentmesh.authz

	  default allow = false
	  default reason = "access denied"

	  violations[msg]{
          input.agent.trust_score < 50
		  msg := "trust_score too low"	  
	}

	violations[msg]{
		  lower(input.agent.status) != "active"
		  msg := "agent is not active"	  
	}

	allow {
	    count(violations) == 0
	}

	reason = "access granted" {
	    allow
	}
`

func TestOPAEngine_Evaluate(t *testing.T) {
	ctx := context.Background()

	engine, err := NewOPAEngine(ctx, samplePolicy, "data.agentmesh.authz")
	if err != nil {
		t.Fatalf("failed to create OPA engine: %v", err)
	}

	makeTestInput := func(status auth.AgentStatus, trustScore int) *mcp.PolicyInput {
		rawArgs := json.RawMessage(`{"a":10, "b":20}`)
		
		return &mcp.PolicyInput{
			TraceID:    "test-trace-id",
			Method: "mcp.MethodToolCall",
			ToolName:   "calculator",
			RawArgs:     &rawArgs,
			Agent: &auth.AgentIdentity{
				AgentID:    "agent-123",
				Status:     status,
				TrustScore: trustScore,
				ExpiresAt:  time.Now().Add(24 * time.Hour),
			},
		}
	}

	testCase := []struct {
		name           string
		input          *mcp.PolicyInput
		expectedAllow  bool
		expectedReason string
		expectedViol   string
	}{
		{
			name:           "Allowed - Active agent with high trust",
			input:          makeTestInput(auth.StatusActive, 80),
			expectedAllow:  true,
			expectedReason: "access granted",
			expectedViol:   "",
		},
		{
			name:           "Denied - Trust score below threshold",
			input:          makeTestInput(auth.StatusActive, 30),
			expectedAllow:  false,
			expectedReason: "access denied",
			expectedViol:   "trust_score too low",
		},
		{
			name:           "Denied - Suspended agent",
			input:          makeTestInput(auth.StatusSuspended, 80),
			expectedAllow:  false,
			expectedReason: "access denied",
			expectedViol:   "agent is not active",
		},
		{
			name:           "Denied - Revoked agent and low trust",
			input:          makeTestInput(auth.StatusRevoked, 10),
			expectedAllow:  false,
			expectedReason: "access denied",
			expectedViol:   "agent is not active",
		},
	}

	for _, tc := range testCase {
		t.Run(tc.name, func(t *testing.T) {
			result, err := engine.Evaluate(ctx, tc.input)
			if err != nil {
				t.Fatalf("Evaluate failed: %v", err)
			}

			if result.Allow != tc.expectedAllow {
				t.Errorf("Expected allow: %v, got: %v", tc.expectedAllow, result.Allow)
			}

			if result.Reason != tc.expectedReason {
				t.Errorf("Expected reason: %v, got: %v", tc.expectedReason, result.Reason)
			}

			if tc.expectedViol == "" {
				if len(result.Violations) != 0 {
					t.Errorf("Expected 0 violations, got %d: %v", len(result.Violations), result.Violations)
				}
			} else {
				found := false
				for _, v := range result.Violations {
					if v == tc.expectedViol {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected violation %q not found in %v", tc.expectedViol, result.Violations)
				}
			}

			if result.EvaluationDuration < 0 {
				t.Errorf("Expected positive evaluation duration, got: %v", result.EvaluationDuration)
			}
		})
	}
}
