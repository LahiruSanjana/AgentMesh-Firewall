package main

import (
	"agentmesh/pkg/auth"
	"agentmesh/pkg/policy"
	"agentmesh/pkg/proxy"
	"context"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	store := auth.NewMemoryIdentityStore()

	store.Set(&auth.AgentIdentity{
		AgentID:       "agent-007",
		TenantID:      "tenant-001",
		KeyHash:       auth.HashKey("ak_live_valid_123456"),
		Status:        auth.StatusActive,
		TrustScore:    90,
		AllowedScopes: []string{"read_file", "tools/call"},
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	})
	store.Set(
		&auth.AgentIdentity{
			AgentID:       "agent-008",
			TenantID:      "tenant-002",
			KeyHash:       auth.HashKey("ak_live_suspended_99999"),
			Status:        auth.StatusSuspended,
			TrustScore:    30,
			AllowedScopes: []string{"write_file", "tools/call"},
			ExpiresAt:     time.Now().Add(1 * time.Hour),
		},
	)

	policyCode, err := os.ReadFile("pkg/policy/agent_mesh.rego")
	if err != nil {
		log.Fatalf("failed to read OPA policy: %v", err)
	}

	engine, err := policy.NewOPAEngine(
		context.Background(),
		string(policyCode),
		"data.agentmesh.authz",
	)
	if err != nil {
		log.Fatalf("failed to create OPA engine: %v", err)
	}

	targetURL := "http://localhost:9000/mcp"
	dispatcher := proxy.NewHTTPDispatcher(targetURL, 10*time.Second)

	handler := proxy.NewProxyHandler(store, engine, dispatcher)

	log.Println("AgentMesh AI Firewall running on :9999...")
	err = http.ListenAndServe(":9999", handler)
	if err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
