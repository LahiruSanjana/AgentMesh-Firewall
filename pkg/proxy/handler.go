package proxy

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"agentmesh/pkg/auth"
	"agentmesh/pkg/mcp"
	"agentmesh/pkg/policy"
)

type ProxyHandler struct {
	store      auth.IdentityResolver
	engine     policy.Engine
	dispatcher Dispatcher
}

func NewProxyHandler(store auth.IdentityResolver, engine policy.Engine, dispatcher Dispatcher) *ProxyHandler {
	return &ProxyHandler{
		store:      store,
		engine:     engine,
		dispatcher: dispatcher,
	}
}

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.URL.Path != "/proxy" && r.URL.Path != "/" {
        http.Error(w, "Not Found", http.StatusNotFound)
        return
    }

	authHeader := r.Header.Get("Authorization")

	token, err := auth.ExtractBearerToken(authHeader)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	keyHash := auth.HashKey(token)

	agent, err := h.store.Resolve(r.Context(), keyHash)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	err = auth.ValidateIdentity(agent, time.Now())
	if err != nil {
		if errors.Is(err, auth.ErrAgentInactive) {
			http.Error(w, "Forbidden: agent is inactive", http.StatusForbidden)
			return
		}
		http.Error(w, "Unauthorized: invalid identity", http.StatusUnauthorized)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	var env mcp.Envelope
	err = json.Unmarshal(body, &env)
	if err != nil {
		http.Error(w, "Invalid JSON-RPC payload", http.StatusBadRequest)
		return
	}

	if err := env.Validate(); err != nil {
		http.Error(w, "Invalid JSON-RPC payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	var traceId = "trace-" + time.Now().Format("20060102150405")
	policyInput, err := mcp.Normalize(&env, traceId, agent)
	if err != nil {
		http.Error(w, "Failed to normalize request", http.StatusBadRequest)
		return
	}

	decision, err := h.engine.Evaluate(r.Context(), policyInput)
	if err != nil {
		http.Error(w, "Failed to evaluate policy", http.StatusInternalServerError)
		return
	}

	if !decision.Allow {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      env.ID,
			"error": map[string]interface{}{
				"code":    -32000,
				"message": decision.Reason,
				"data":    decision.Violations,
			},
		})
		return
	}

	resp, err := h.dispatcher.Dispatch(r.Context(), "", body, r.Header)
	if err != nil {
		http.Error(w, "Bad Gateway: failed to dispatch request to downstream", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}
