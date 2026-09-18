package mcp

import (
	"encoding/json"
	"testing"
)

func TestEnvelopeValidationAndClassification(t *testing.T) {

	tests := []struct {
		name         string
		payload      string
		expectErr    bool
		expectedType MessageType
	}{
		{
			name:         "Valid Request",
			payload:      `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`,
			expectErr:    false,
			expectedType: MessageTypeRequest,
		},
		{
			name:         "Valid Notification",
			payload:      `{"jsonrpc":"2.0","method":"notify"}`,
			expectErr:    false,
			expectedType: MessageTypeNotification,
		},
		{
			name:         "Invalid JSON-RPC Version",
			payload:      `{"jsonrpc":"1.0","id":1,"method":"test"}`,
			expectErr:    true,
			expectedType: MessageTypeUnknown,
		},
		{
			name:         "Ambiguous Payload (Method + Result)",
			payload:      `{"jsonrpc":"2.0","id":1,"method":"test","result":{"ok":true}}`,
			expectErr:    true,
			expectedType: MessageTypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var env Envelope
			
			err := json.Unmarshal([]byte(tt.payload), &env)
			if err != nil {
				t.Fatalf("JSON parse error: %v", err)
			}

			msgType, err := env.Classify()
			if (err != nil) != tt.expectErr {
				t.Errorf("expected error: %v, got: %v", tt.expectErr, err)
			}

			if !tt.expectErr && msgType != tt.expectedType {
				t.Errorf("expected message type: %v, got: %v", tt.expectedType, msgType)
			}

		})
	}
}
