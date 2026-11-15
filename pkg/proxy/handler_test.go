package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"agentmesh/pkg/auth"
	"agentmesh/pkg/config"
	"agentmesh/pkg/mcp"
	"agentmesh/pkg/policy"
)

type mockPolicyEngine struct {
	allow       bool
	nilDecision bool
}

func (m *mockPolicyEngine) Evaluate(ctx context.Context, input *mcp.PolicyInput) (*policy.Decision, error) {
	if m.nilDecision {
		return nil, nil
	}
	return &policy.Decision{
		Allow:  m.allow,
		Reason: "mock decision",
	}, nil
}

type mockDispatcher struct {
	statusCode int
	body       string
	targetURL  string
}

func (m *mockDispatcher) Dispatch(ctx context.Context, targetURL string, rawBody []byte, originalHeaders http.Header) (*http.Response, error) {
	m.targetURL = targetURL
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
	defer handler.Stop()
	defer deniedHandler.Stop()

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

		if mockDisp.targetURL != "" {
			t.Fatalf("handler must use the dispatcher's configured target URL, got %q", mockDisp.targetURL)
		}
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

	t.Run("Nil policy decision returns 403 instead of panicking", func(t *testing.T) {
		handler := NewProxyHandler(store, &mockPolicyEngine{nilDecision: true}, mockDisp, 100)
		req := httptest.NewRequest(http.MethodPost, "/proxy", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`))
		req.Header.Set("Authorization", "Bearer "+validTokeen)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Fatalf("Expected status %d, got %d", http.StatusForbidden, rr.Code)
		}
	})

	t.Run("Oversized body returns 413", func(t *testing.T) {
		handler := NewProxyHandler(store, allowPolicyEngine, mockDisp, 100)
		body := bytes.Repeat([]byte("a"), maxRequestBodySize+1)
		req := httptest.NewRequest(http.MethodPost, "/proxy", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+validTokeen)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("Expected status %d, got %d", http.StatusRequestEntityTooLarge, rr.Code)
		}
	})

	t.Run("Health and readiness endpoints are unauthenticated", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"status":"ok"`) {
			t.Fatalf("unexpected health response: %d %s", rr.Code, rr.Body.String())
		}

		req = httptest.NewRequest(http.MethodGet, "/readyz", nil)
		rr = httptest.NewRecorder()
		readyHandler := NewProxyHandlerWithConfig(store, allowPolicyEngine, mockDisp, config.Defaults())
		readyHandler.ServeHTTP(rr, req)
		readyHandler.Stop()
		if rr.Code != http.StatusOK {
			t.Fatalf("expected ready response, got %d", rr.Code)
		}
	})

	t.Run("Notification returns accepted without response body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
		req.Header.Set("Authorization", "Bearer "+validTokeen)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusAccepted || rr.Body.Len() != 0 {
			t.Fatalf("expected empty 202 notification response, got %d %q", rr.Code, rr.Body.String())
		}
	})
}
