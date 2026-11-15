package policy

import (
	"agentmesh/pkg/auth"
	"agentmesh/pkg/mcp"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

const samplePolicy = `
package agentmesh.authz
default allow = false
default reason = "access denied"
violations[msg] { input.agent.trust_score < 50; msg := "trust_score too low" }
violations[msg] { lower(input.agent.status) != "active"; msg := "agent is not active" }
allow { count(violations) == 0 }
reason = "access granted" { allow }
`

func TestOPAEngine_Evaluate(t *testing.T) {
	engine, err := NewOPAEngine(context.Background(), samplePolicy, "data.agentmesh.authz")
	if err != nil {
		t.Fatal(err)
	}
	makeTestInput := func(status auth.AgentStatus, trustScore int) *mcp.PolicyInput {
		rawArgs := json.RawMessage(`{"a":10,"b":20}`)
		return &mcp.PolicyInput{
			TraceID: "test-trace-id", Method: "mcp.MethodToolCall", ToolName: "calculator",
			RawArgs: &rawArgs, Agent: &auth.AgentIdentity{
				AgentID: "agent-123", Status: status, TrustScore: trustScore,
				ExpiresAt: time.Now().Add(24 * time.Hour),
			},
		}
	}
	tests := []struct {
		name      string
		input     *mcp.PolicyInput
		allow     bool
		reason    string
		violation string
	}{
		{"allowed", makeTestInput(auth.StatusActive, 80), true, "access granted", ""},
		{"low trust", makeTestInput(auth.StatusActive, 30), false, "access denied", "trust_score too low"},
		{"suspended", makeTestInput(auth.StatusSuspended, 80), false, "access denied", "agent is not active"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := engine.Evaluate(context.Background(), tc.input)
			if err != nil {
				t.Fatal(err)
			}
			if result.Allow != tc.allow || result.Reason != tc.reason {
				t.Fatalf("unexpected result: %+v", result)
			}
			if tc.violation != "" && !containsViolation(result.Violations, tc.violation) {
				t.Fatalf("missing violation %q in %v", tc.violation, result.Violations)
			}
		})
	}
}

func TestAgentMeshPolicyDeniesUnknownMethodAndTenantViolation(t *testing.T) {
	code, err := os.ReadFile("agent_mesh.rego")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewOPAEngine(context.Background(), string(code), "data.agentmesh.authz")
	if err != nil {
		t.Fatal(err)
	}
	agent := &auth.AgentIdentity{
		AgentID: "agent-1", TenantID: "tenant-a", Status: auth.StatusActive,
		TrustScore: 90, AllowedScopes: []string{"tools/list"},
	}
	unknown := &mcp.PolicyInput{Agent: agent, Identity: agent, Method: "unknown/method"}
	decision, err := engine.Evaluate(context.Background(), unknown)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allow || !containsViolation(decision.Violations, "method_not_allowed") {
		t.Fatalf("expected unknown method denial, got %+v", decision)
	}
	tenant := &mcp.PolicyInput{Agent: agent, Identity: agent, Method: mcp.MethodToolList, TargetTenant: "tenant-b"}
	decision, err = engine.Evaluate(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allow || !containsViolation(decision.Violations, "tenant_scope_violation") {
		t.Fatalf("expected tenant denial, got %+v", decision)
	}
}

func containsViolation(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
