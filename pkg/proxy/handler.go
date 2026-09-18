package proxy

import (
	"agentmesh/pkg/auth"
	"agentmesh/pkg/mcp"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

type ProxyHandler struct {
	store auth.IdentityResolver
}

func NewProxyHandler(store auth.IdentityResolver) *ProxyHandler {
	return &ProxyHandler{
		store: store,
	}
}

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
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
		http.Error(w, "Request processed successfully", http.StatusUnauthorized)
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(policyInput)
}

