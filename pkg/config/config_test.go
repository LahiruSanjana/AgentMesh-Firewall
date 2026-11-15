package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadPrecedence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agentmesh.yaml")
	if err := os.WriteFile(path, []byte(`
listen_addr: "file:9999"
downstream_url: "http://file.example/mcp"
policy_path: "file.rego"
downstream_timeout: 2s
`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENTMESH_LISTEN_ADDR", "env:9999")
	t.Setenv("AGENTMESH_DOWNSTREAM_URL", "http://env.example/mcp")
	cfg, err := LoadFromFlags([]string{"--config", path, "--listen", "cli:9999"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != "cli:9999" || cfg.DownstreamURL != "http://env.example/mcp" || cfg.PolicyPath != "file.rego" {
		t.Fatalf("unexpected precedence result: %+v", cfg)
	}
	if cfg.DownstreamTimeout != 2*time.Second {
		t.Fatalf("expected YAML duration, got %s", cfg.DownstreamTimeout)
	}
}

func TestLoadMissingConfigUsesDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr == "" || cfg.DownstreamURL == "" || cfg.PolicyPath == "" {
		t.Fatalf("expected safe defaults: %+v", cfg)
	}
}
