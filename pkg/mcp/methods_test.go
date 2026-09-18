package mcp

import (
	"testing"
	"encoding/json"
	"agentmesh/pkg/auth"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		name             string
		payload          string
		expectedError    bool
		expectedTool     string
		expectedResource string
	}{
		{
			name:          "Valid Tool Call",
			payload:       `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/hosts"}}}`,
			expectedError: false,
			expectedTool:  "read_file",
		},
		{
			name:          "Missing Params for Tool Call",
			payload:       `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`,
			expectedError: true,
			expectedTool:  "",
		}, {
			name:          "Empty Tool Name",
			payload:       `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"   "}}`,
			expectedError: true,
			expectedTool:  "",
		}, {
			name:          "Arguments as Array",
			payload:       `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":[1, 2, 3]}}`,
			expectedError: true,
			expectedTool:  "",
		}, {
			name:          "Valid Resource Read",
			payload:       `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"s3://bucket/data.csv"}}`,
			expectedError: false,
			expectedTool:  "",
		},
	}

	mockAgent := &auth.AgentIdentity{
		AgentID:    "agent-007",
        TenantID:   "tenant-corp",
        Status:     auth.StatusActive,
        TrustScore: 90,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var env Envelope

			err := json.Unmarshal([]byte(tt.payload), &env)
			if err != nil {
				t.Fatalf("Failed to unmarshal payload: %v", err)
			}

			policyInput, err := Normalize(&env, "trace-123", mockAgent)

			if (err != nil) != tt.expectedError {
				t.Errorf("Normalize() error = %v, expectedError %v", err, tt.expectedError)
				return
			}

			if !tt.expectedError {
				if policyInput.ToolName != tt.expectedTool {
					t.Errorf("Expected ToolName '%s', got '%s'", tt.expectedTool, policyInput.ToolName)
				}
				if policyInput.TraceID != "trace-123" {
					t.Errorf("Expected TraceID 'trace-123', got '%s'", policyInput.TraceID)
				}
			}
		})
	}
}
