package mcp

import (
	"agentmesh/pkg/auth"
	"encoding/json"
	"strings"
	"testing"
)

func TestErrorResponsePreservesIDAndData(t *testing.T) {
	id := RequestID([]byte(`{"jsonrpc":"2.0","id":7,"method":"tools/call"}`))
	response := ErrorResponse(id, CodePolicyError, "blocked", ErrorData{
		Violation: "tool_not_permitted",
		Action:    "use an allowed tool",
		TraceID:   "trace-1",
	})
	data, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["id"] != float64(7) {
		t.Fatalf("expected preserved id, got %v", decoded["id"])
	}
}

func TestRequestIDReturnsNilForInvalidPayload(t *testing.T) {
	if RequestID([]byte("not-json")) != nil {
		t.Fatal("expected nil request ID")
	}
}

func TestPolicyInputRedactsKeyHash(t *testing.T) {
	input := &PolicyInput{
		Agent: &auth.AgentIdentity{
			AgentID: "agent-1", TenantID: "tenant-1", KeyHash: "secret-hash",
			Status: auth.StatusActive, TrustScore: 90,
		},
		Identity: &auth.AgentIdentity{
			AgentID: "agent-1", TenantID: "tenant-1", KeyHash: "secret-hash",
			Status: auth.StatusActive, TrustScore: 90,
		},
		Method: MethodToolList,
	}
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "secret-hash") || strings.Contains(string(data), "key_hash") {
		t.Fatalf("sensitive identity field leaked: %s", data)
	}
}
