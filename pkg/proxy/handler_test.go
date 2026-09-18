package proxy

import (
	"agentmesh/pkg/auth"
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProxyHandler_ServeHTTP(t *testing.T) {
	// 1.Setup mock store & seed identities
	store := auth.NewMemoryIdentityStore()

	validTokeen := "ak_live_valid_123456"
	validHash := auth.HashKey(validTokeen)
	store.Set(&auth.AgentIdentity{
		AgentID:    "agent-007",
		TenantID:   "tenant-001",
		KeyHash:    validHash,
		Status:     auth.StatusActive,
		TrustScore: 90,
		ExpiresAt:  time.Now().Add(1 * time.Hour),
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
		AgentID: "agent-expire",
		TenantID: "tenant-bita",
		KeyHash: expeiredHash,
		Status: auth.StatusActive,
		TrustScore: 50,
		ExpiresAt : time.Now().Add(-1 * time.Hour),
	})

	handler := NewProxyHandler(store)
	test := []struct {
		name         string
		method       string
		authHeader   string
		body         string
		expectedStatus int
	} {
		{
			name:          "Clean header",
			method:        http.MethodPost,
			authHeader:    "Bearer " + validTokeen,
			body:          `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp"}}}`,
			expectedStatus: http.StatusOK,
		},
		{
			name: 		"Missing Authorization Header",
			method: 	http.MethodPost,
			authHeader: "",
			body: 		`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: 		"Malformed",
			method: 	http.MethodPost,
			authHeader: "secret-key-123",
			body: 		`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: 		"Suspended Agent",
			method: 	http.MethodPost,
			authHeader: "Bearer " + suspendedToken,
			body: 		`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`,
			expectedStatus: http.StatusForbidden,
		},
		{
			name: 		"Expired Token",
			method: 	http.MethodPost,
			authHeader: "Bearer " + expiredToken,
			body: 		`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: 		"Invalid Token",
			method: 	http.MethodPost,
			authHeader: "Bearer invalid-token-xyz",
			body: 		`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "Method Not Allowed",
			method: http.MethodGet,
			authHeader: "Bearer " + validTokeen,
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`,
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
}
