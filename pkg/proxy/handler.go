package proxy

import (
	"agentmesh/pkg/auth"
	"agentmesh/pkg/config"
	"agentmesh/pkg/limiter"
	"agentmesh/pkg/mcp"
	"agentmesh/pkg/policy"
	"agentmesh/pkg/telemetry"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const maxRequestBodySize = 1 << 20

type RequestDispatcher interface {
	Dispatch(ctx context.Context, targetURL string, rawBody []byte, originalHeaders http.Header) (*http.Response, error)
}

type ProxyHandler struct {
	store                *auth.MemoryIdentityStore
	engine               policy.Engine
	dispatcher           RequestDispatcher
	logger               *telemetry.AuditLogger
	rateLimiter          *limiter.RateLimiter
	targetURL            string
	maxRequestBodyBytes  int64
	maxResponseBodyBytes int64
}

func NewProxyHandler(store *auth.MemoryIdentityStore, engine policy.Engine, dispatcher RequestDispatcher, rateLimitPerMin int) *ProxyHandler {
	cfg := config.Defaults()
	cfg.RateLimitPerMinute = rateLimitPerMin
	cfg.DownstreamURL = ""
	return NewProxyHandlerWithConfig(store, engine, dispatcher, cfg)
}

func NewProxyHandlerWithConfig(store *auth.MemoryIdentityStore, engine policy.Engine, dispatcher RequestDispatcher, cfg config.Config) *ProxyHandler {
	if cfg.MaxRequestBodyBytes <= 0 {
		cfg.MaxRequestBodyBytes = maxRequestBodySize
	}
	if cfg.MaxResponseBodyBytes <= 0 {
		cfg.MaxResponseBodyBytes = 4 << 20
	}
	return &ProxyHandler{
		store: store, engine: engine, dispatcher: dispatcher,
		logger:               telemetry.NewAuditLogger(),
		rateLimiter:          limiter.NewRateLimiter(cfg.RateLimitPerMinute, time.Minute),
		targetURL:            cfg.DownstreamURL,
		maxRequestBodyBytes:  cfg.MaxRequestBodyBytes,
		maxResponseBodyBytes: cfg.MaxResponseBodyBytes,
	}
}

func (h *ProxyHandler) Stop() {
	if h.rateLimiter != nil {
		h.rateLimiter.Stop()
	}
}

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	if r.URL.Path == "/readyz" && r.Method == http.MethodGet {
		if h.engine == nil || h.dispatcher == nil || h.targetURL == "" {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
		return
	}
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, nil, mcp.CodeInvalidRequest, "Only POST is supported", mcp.ErrorData{
			Violation: "method_not_allowed", Action: "Send an HTTP POST request.", Retryable: false,
		})
		return
	}

	limit := h.maxRequestBodyBytes
	if limit <= 0 {
		limit = maxRequestBodySize
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	bodyBytes, bodyErr := io.ReadAll(r.Body)
	requestID := mcp.RequestID(bodyBytes)
	if bodyErr != nil {
		h.writeError(w, http.StatusRequestEntityTooLarge, requestID, mcp.CodeInvalidRequest, "Request body could not be read", mcp.ErrorData{
			Violation: "request_body_invalid", Action: "Send a valid request within the configured size limit.", Retryable: false,
		})
		h.audit(r.RemoteAddr, nil, "request_body_invalid", false, http.StatusRequestEntityTooLarge)
		return
	}
	clientIP := r.RemoteAddr
	if token, err := auth.ExtractBearerToken(r.Header.Get("Authorization")); err != nil {
		h.writeError(w, http.StatusUnauthorized, requestID, mcp.CodeInvalidRequest, "Authentication required", mcp.ErrorData{
			Violation: "authentication_required", Action: "Provide a valid Bearer token.", Retryable: false,
		})
		h.audit(clientIP, nil, "authentication_required", false, http.StatusUnauthorized)
		return
	} else {
		keyHash := auth.HashKey(token)
		identity, resolveErr := h.store.Resolve(r.Context(), keyHash)
		if resolveErr != nil || auth.ValidateIdentity(identity, time.Now()) != nil {
			h.writeError(w, http.StatusForbidden, requestID, mcp.CodeInvalidRequest, "Agent is not authorized", mcp.ErrorData{
				Violation: "agent_not_authorized", Action: "Use an active, unexpired agent credential.", Retryable: false,
			})
			h.audit(clientIP, nil, "agent_not_authorized", false, http.StatusForbidden)
			return
		}
		h.serveAuthorized(w, r, identity, requestID, bodyBytes, clientIP)
	}
}

func (h *ProxyHandler) serveAuthorized(w http.ResponseWriter, r *http.Request, identity *auth.AgentIdentity, requestID *json.RawMessage, bodyBytes []byte, clientIP string) {
	if !h.rateLimiter.Allow(identity.AgentID) {
		h.writeError(w, http.StatusTooManyRequests, requestID, mcp.CodePolicyError, "Rate limit exceeded", mcp.ErrorData{
			Violation: "rate_limit_exceeded", Action: "Wait before retrying the request.", Retryable: true,
		})
		h.audit(clientIP, identity, "rate_limit_exceeded", false, http.StatusTooManyRequests)
		return
	}

	requestID = mcp.RequestID(bodyBytes)
	envelope, err := mcp.ParseEnvelope(bodyBytes)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, requestID, mcp.CodeInvalidRequest, "Invalid JSON-RPC request", mcp.ErrorData{
			Violation: "invalid_jsonrpc", Action: "Send a valid JSON-RPC 2.0 request.", Retryable: false,
		})
		h.audit(clientIP, identity, "invalid_jsonrpc", false, http.StatusBadRequest)
		return
	}
	traceID := fmt.Sprintf("trace-%d", time.Now().UnixNano())
	input, err := mcp.Normalize(envelope, traceID, identity)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, envelope.ID, mcp.CodeInvalidRequest, "Invalid MCP parameters", mcp.ErrorData{
			Violation: "invalid_mcp_params", Method: methodOf(envelope), Action: "Correct the MCP method parameters and retry.", TraceID: traceID,
		})
		h.audit(clientIP, identity, "invalid_mcp_params", false, http.StatusBadRequest)
		return
	}
	if h.engine == nil {
		h.writeError(w, http.StatusInternalServerError, envelope.ID, mcp.CodeInternalError, "AgentMesh policy engine is unavailable", mcp.ErrorData{
			Violation: "policy_engine_unavailable", Method: string(input.Method), TraceID: traceID,
		})
		h.audit(clientIP, identity, "policy_engine_unavailable", false, http.StatusInternalServerError)
		return
	}
	decision, err := h.engine.Evaluate(r.Context(), input)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, envelope.ID, mcp.CodeInternalError, "AgentMesh policy evaluation failed", mcp.ErrorData{
			Violation: "policy_evaluation_error", Method: string(input.Method), Tool: input.ToolName,
			Action: "Retry after checking the configured policy.", Retryable: true, TraceID: traceID,
		})
		h.audit(clientIP, identity, "policy_evaluation_error", false, http.StatusInternalServerError)
		return
	}
	if decision == nil || !decision.Allow {
		violation := "policy_denied"
		if decision != nil && len(decision.Violations) > 0 {
			violation = decision.Violations[0]
		}
		action := "Use a method, tool, or resource allowed by the AgentMesh policy."
		if decision != nil && decision.Action != "" {
			action = decision.Action
		}
		h.writeError(w, http.StatusForbidden, envelope.ID, mcp.CodePolicyError, "Request blocked by AgentMesh security policy", mcp.ErrorData{
			Violation: violation, Method: string(input.Method), Tool: input.ToolName,
			Action: action, Retryable: decision != nil && decision.Retryable, TraceID: traceID,
		})
		h.audit(clientIP, identity, violation, false, http.StatusForbidden)
		return
	}
	if h.dispatcher == nil {
		h.writeError(w, http.StatusInternalServerError, envelope.ID, mcp.CodeInternalError, "Downstream dispatcher is unavailable", mcp.ErrorData{
			Violation: "dispatcher_unavailable", Method: string(input.Method), TraceID: traceID,
		})
		h.audit(clientIP, identity, "dispatcher_unavailable", false, http.StatusInternalServerError)
		return
	}
	resp, err := h.dispatcher.Dispatch(r.Context(), h.targetURL, bodyBytes, r.Header)
	if err != nil || resp == nil || resp.Body == nil {
		h.writeError(w, http.StatusBadGateway, envelope.ID, mcp.CodeInternalError, "Downstream MCP service is unavailable", mcp.ErrorData{
			Violation: "downstream_unavailable", Action: "Verify the downstream MCP server and retry.", Retryable: true, TraceID: traceID,
		})
		h.audit(clientIP, identity, "downstream_unavailable", false, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	responseLimit := h.maxResponseBodyBytes
	if responseLimit <= 0 {
		responseLimit = 4 << 20
	}
	responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, responseLimit+1))
	if readErr != nil || int64(len(responseBody)) > responseLimit {
		h.writeError(w, http.StatusBadGateway, envelope.ID, mcp.CodeInternalError, "Downstream response is invalid or too large", mcp.ErrorData{
			Violation: "downstream_response_invalid", Action: "Reduce the downstream response size or adjust the gateway limit.", Retryable: false, TraceID: traceID,
		})
		h.audit(clientIP, identity, "downstream_response_invalid", false, http.StatusBadGateway)
		return
	}
	for key, values := range filterHopByHopHeaders(resp.Header) {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	if envelope.ID == nil {
		w.WriteHeader(http.StatusAccepted)
		h.audit(clientIP, identity, "notification_dispatched", true, http.StatusAccepted)
		return
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(responseBody)
	h.audit(clientIP, identity, "authorized_and_dispatched", true, resp.StatusCode)
}

func (h *ProxyHandler) writeError(w http.ResponseWriter, status int, id *json.RawMessage, code int, message string, data mcp.ErrorData) {
	if id == nil {
		raw := json.RawMessage("null")
		id = &raw
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(mcp.ErrorResponse(id, code, message, data))
}

func (h *ProxyHandler) audit(clientIP string, identity *auth.AgentIdentity, reason string, allowed bool, status int) {
	entry := telemetry.AuditLog{ClientIP: clientIP, Reason: reason, Allowed: allowed, StatusCode: status}
	if identity != nil {
		entry.AgentID, entry.TenantID = identity.AgentID, identity.TenantID
	}
	h.logger.Log(entry)
}

func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func methodOf(env *mcp.Envelope) string {
	if env != nil && env.Method != nil {
		return *env.Method
	}
	return ""
}
