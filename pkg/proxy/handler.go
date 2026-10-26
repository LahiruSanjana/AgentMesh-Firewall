package proxy

import (
	"agentmesh/pkg/auth"
	"agentmesh/pkg/limiter"
	"agentmesh/pkg/mcp"
	"agentmesh/pkg/policy"
	"agentmesh/pkg/telemetry"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

type PolicyEvaluator interface {
	Evaluate(ctx context.Context, input map[string]interface{}) (*policy.Decision, error)
}

type RequestDispatcher interface {
	Dispatch(ctx context.Context, targetURL string, rawBody []byte, originalHeaders http.Header) (*http.Response, error)
}

type ProxyHandler struct {
	store       *auth.MemoryIdentityStore
	engine      policy.Engine
	dispatcher  RequestDispatcher
	logger      *telemetry.AuditLogger
	rateLimiter *limiter.RateLimiter
}

func NewProxyHandler(
	store *auth.MemoryIdentityStore,
	engine policy.Engine,
	dispatcher RequestDispatcher,
	rateLimitPerMin int,
) *ProxyHandler {
	return &ProxyHandler{
		store:       store,
		engine:      engine,
		dispatcher:  dispatcher,
		logger:      telemetry.NewAuditLogger(),
		rateLimiter: limiter.NewRateLimiter(rateLimitPerMin, 1*time.Minute),
	}
}

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIP := r.RemoteAddr

	// 1. Bearer Token Auth
	token, err := auth.ExtractBearerToken(r.Header.Get("Authorization"))
	if err != nil {
		h.logger.Log(telemetry.AuditLog{
			Allowed:    false,
			Reason:     "Missing or invalid Authorization header",
			StatusCode: http.StatusUnauthorized,
			ClientIP:   clientIP,
		})
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	keyHash := auth.HashKey(token)
	identity, err := h.store.Resolve(r.Context(), keyHash)
	if err != nil || auth.ValidateIdentity(identity, time.Now()) != nil {
		h.logger.Log(telemetry.AuditLog{
			Allowed:    false,
			Reason:     "Invalid token or suspended agent",
			StatusCode: http.StatusForbidden,
			ClientIP:   clientIP,
		})
		http.Error(w, "Forbidden: agent is inactive", http.StatusForbidden)
		return
	}

	// 2. Rate Limiting Check (Per Agent)
	if !h.rateLimiter.Allow(identity.AgentID) {
		h.logger.Log(telemetry.AuditLog{
			AgentID:    identity.AgentID,
			TenantID:   identity.TenantID,
			Allowed:    false,
			Reason:     "Rate limit exceeded (Too Many Requests)",
			StatusCode: http.StatusTooManyRequests,
			ClientIP:   clientIP,
		})
		http.Error(w, "Too Many Requests: Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// Read Body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// 3. MCP Envelope Parsing & Normalization
	envelope, err := mcp.ParseEnvelope(bodyBytes)
	if err != nil {
		h.logger.Log(telemetry.AuditLog{
			AgentID:    identity.AgentID,
			TenantID:   identity.TenantID,
			Allowed:    false,
			Reason:     "Invalid JSON-RPC payload",
			StatusCode: http.StatusBadRequest,
			ClientIP:   clientIP,
		})
		http.Error(w, "Invalid JSON-RPC payload", http.StatusBadRequest)
		return
	}

	traceID := fmt.Sprintf("trace-%d", time.Now().UnixNano())
	policyInputStruct, err := mcp.Normalize(envelope, traceID, identity)
	if err != nil {
		h.logger.Log(telemetry.AuditLog{
			AgentID:    identity.AgentID,
			TenantID:   identity.TenantID,
			Allowed:    false,
			Reason:     "Normalization failed: " + err.Error(),
			StatusCode: http.StatusBadRequest,
			ClientIP:   clientIP,
		})
		http.Error(w, "Invalid MCP Payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 4. OPA Policy Evaluation
	decision, err := h.engine.Evaluate(r.Context(), policyInputStruct)
	if err != nil || !decision.Allow {
		reason := "Policy violation"
		if decision != nil && decision.Reason != "" {
			reason = decision.Reason
		}
		h.logger.Log(telemetry.AuditLog{
			AgentID:    identity.AgentID,
			TenantID:   identity.TenantID,
			Method:     string(policyInputStruct.Method),
			ToolName:   policyInputStruct.ToolName,
			Allowed:    false,
			Reason:     reason,
			StatusCode: http.StatusForbidden,
			ClientIP:   clientIP,
		})
		http.Error(w, "Forbidden: "+reason, http.StatusForbidden)
		return
	}

	// 5. Audit Log Success & Dispatching to Downstream
	resp, err := h.dispatcher.Dispatch(r.Context(), r.URL.Path, bodyBytes, r.Header)
	if err != nil {
		h.logger.Log(telemetry.AuditLog{
			AgentID:    identity.AgentID,
			TenantID:   identity.TenantID,
			Allowed:    false,
			Reason:     "Downstream dispatch failed: " + err.Error(),
			StatusCode: http.StatusBadGateway,
			ClientIP:   clientIP,
		})
		http.Error(w, "Bad Gateway: failed to dispatch request to downstream", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy headers from downstream to client response
	for k, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(k, v)
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)

	h.logger.Log(telemetry.AuditLog{
		AgentID:    identity.AgentID,
		TenantID:   identity.TenantID,
		Method:     string(policyInputStruct.Method),
		ToolName:   policyInputStruct.ToolName,
		Allowed:    true,
		Reason:     "Authorized and dispatched",
		StatusCode: resp.StatusCode,
		ClientIP:   clientIP,
	})
}