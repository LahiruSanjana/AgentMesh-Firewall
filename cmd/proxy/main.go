package main

import (
	"agentmesh/pkg/auth"
	"agentmesh/pkg/config"
	"agentmesh/pkg/policy"
	"agentmesh/pkg/proxy"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	cfg, err := config.LoadFromFlags(os.Args[1:])
	if err != nil {
		log.Printf("configuration error: %v", err)
		return
	}
	if cfg.PolicyPath == config.Version {
		fmt.Println(config.Version)
		return
	}

	store := auth.NewMemoryIdentityStore()
	for _, identity := range cfg.IdentitiesForStore() {
		store.Set(identity)
	}

	policyCode, err := os.ReadFile(cfg.PolicyPath)
	if err != nil {
		log.Printf("failed to read OPA policy: %v", err)
		return
	}
	engine, err := policy.NewOPAEngine(context.Background(), string(policyCode), "data.agentmesh.authz")
	if err != nil {
		log.Printf("failed to create OPA engine: %v", err)
		return
	}

	dispatcher := proxy.NewHTTPDispatcher(cfg.DownstreamURL, cfg.DownstreamTimeout)
	handler := proxy.NewProxyHandlerWithConfig(store, engine, dispatcher, cfg)
	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}

	serverErrors := make(chan error, 1)
	go func() {
		log.Printf("AgentMesh Firewall %s listening on %s", config.Version, cfg.ListenAddr)
		serverErrors <- server.ListenAndServe()
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Printf("server failed: %v", err)
		}
	case <-signals:
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}
	handler.Stop()
}
