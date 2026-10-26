package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"agentmesh/pkg/auth"
	"agentmesh/pkg/policy"
	"agentmesh/pkg/mcp"
)

type mockPolicyEngine struct {
	allow bool
}

func (m *mockPolicyEngine) Evaluate(ctx context.Context, input *mcp.PolicyInput, ) (*policy.Decision, error) {
    return &policy.Decision{
        Allow:  m.allow,
        Reason: "mock decision",
    }, nil
}

type mockDispatcher struct {
	statusCode int
	body       string
}

func (m *mockDispatcher) Dispatch(ctx context.Context, targetURL string, rawBody []byte, originalHeaders http.Header) (*http.Response, error) {
	resp := &http.Response{
		StatusCode: m.statusCode,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString(m.body)),
	}
	resp.Header.Set("Content-Type", "application/json")
	return resp, nil
}

func TestProxyHandler_ServeHTTP(t *testing.T) {
	// 1. Setup mock store & seed identities
	store := auth.NewMemoryIdentityStore()

	validTokeen := "ak_live_valid_123456"
	validHash := auth.HashKey(validTokeen)
	store.Set(&auth.AgentIdentity{
		AgentID:       "agent-007",
		TenantID:      "tenant-001",
		KeyHash:       validHash,
		Status:        auth.StatusActive,
		TrustScore:    90,
		AllowedScopes: []string{"read_file"},
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	})

	suspendedToken := "ak_live_suspended_99999"
	suspendedHash := auth.HashKey(suspendedToken)
	store.Set(&auth.AgentIdentity{
		AgentID:    "agent-bad",
		TenantID:   "tenant-alpha",
		KeyHash:    suspendedHash,
		Status:     auth.StatusSuspended,
		TrustScore: 20,
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	})

	expiredToken := "ak_live_expired_00000"
	expeiredHash := auth.HashKey(expiredToken)
	store.Set(&auth.AgentIdentity{
		AgentID:    "agent-expire",
		TenantID:   "tenant-bita",
		KeyHash:    expeiredHash,
		Status:     auth.StatusActive,
		TrustScore: 50,
		ExpiresAt:  time.Now().Add(-1 * time.Hour),
	})

	allowPolicyEngine := &mockPolicyEngine{allow: true}
	deniedPolicyEngine := &mockPolicyEngine{allow: false}

	mockDisp := &mockDispatcher{
		statusCode: http.StatusOK,
		body:       `{"jsonrpc":"2.0","id":1,"result":{"status":"success"}}`,
	}

	handler := NewProxyHandler(store, allowPolicyEngine, mockDisp, 100)
	deniedHandler := NewProxyHandler(store, deniedPolicyEngine, mockDisp, 100)

	test := []struct {
		name           string
		method         string
		authHeader     string
		body           string
		expectedStatus int
	}{
		{
			name:           "Clean header",
			method:         http.MethodPost,
			authHeader:     "Bearer " + validTokeen,
			body:           `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp"}}}`,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Missing Authorization Header",
			method:         http.MethodPost,
			authHeader:     "",
			body:           `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Malformed",
			method:         http.MethodPost,
			authHeader:     "secret-key-123",
			body:           `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Suspended Agent",
			method:         http.MethodPost,
			authHeader:     "Bearer " + suspendedToken,
			body:           `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`,
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "Expired Token",
			method:         http.MethodPost,
			authHeader:     "Bearer " + expiredToken,
			body:           `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`,
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "Invalid Token",
			method:         http.MethodPost,
			authHeader:     "Bearer invalid-token-xyz",
			body:           `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`,
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "Method Not Allowed",
			method:         http.MethodGet,
			authHeader:     "Bearer " + validTokeen,
			body:           `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`,
			expectedStatus: http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/proxy", bytes.NewBufferString(tt.body))
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}

	t.Run("Policy Denied - Returns 403 Forbidden", func(t *testing.T) {
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp"}}}`
		req := httptest.NewRequest(http.MethodPost, "/proxy", bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer "+validTokeen)

		rr := httptest.NewRecorder()
		deniedHandler.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("Expected status %d, got %d", http.StatusForbidden, rr.Code)
		}
	})
}