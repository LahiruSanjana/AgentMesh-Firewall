package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"agentmesh/pkg/auth"
	"gopkg.in/yaml.v3"
)

const Version = "1.0.0"

type Config struct {
	ListenAddr           string           `yaml:"listen_addr"`
	DownstreamURL        string           `yaml:"downstream_url"`
	PolicyPath           string           `yaml:"policy_path"`
	RateLimitPerMinute   int              `yaml:"rate_limit_per_minute"`
	DownstreamTimeout    time.Duration    `yaml:"downstream_timeout"`
	MaxRequestBodyBytes  int64            `yaml:"max_request_body_bytes"`
	MaxResponseBodyBytes int64            `yaml:"max_response_body_bytes"`
	ReadHeaderTimeout    time.Duration    `yaml:"read_header_timeout"`
	ReadTimeout          time.Duration    `yaml:"read_timeout"`
	WriteTimeout         time.Duration    `yaml:"write_timeout"`
	IdleTimeout          time.Duration    `yaml:"idle_timeout"`
	Identities           []IdentityConfig `yaml:"identities"`
}

type IdentityConfig struct {
	AgentID       string    `yaml:"agent_id"`
	TenantID      string    `yaml:"tenant_id"`
	TokenHash     string    `yaml:"token_hash"`
	Status        string    `yaml:"status"`
	TrustScore    int       `yaml:"trust_score"`
	AllowedScopes []string  `yaml:"allowed_scopes"`
	ExpiresAt     time.Time `yaml:"expires_at"`
}

func Defaults() Config {
	return Config{
		ListenAddr:           "127.0.0.1:9999",
		DownstreamURL:        "http://127.0.0.1:9000/mcp",
		PolicyPath:           "pkg/policy/agent_mesh.rego",
		RateLimitPerMinute:   60,
		DownstreamTimeout:    10 * time.Second,
		MaxRequestBodyBytes:  1 << 20,
		MaxResponseBodyBytes: 4 << 20,
		ReadHeaderTimeout:    5 * time.Second,
		ReadTimeout:          30 * time.Second,
		WriteTimeout:         30 * time.Second,
		IdleTimeout:          60 * time.Second,
	}
}

func Load(path string) (Config, error) {
	cfg := Defaults()
	if path == "" {
		path = "agentmesh.yaml"
	}
	if data, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return Config{}, fmt.Errorf("parse config %q: %w", path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return Config{}, fmt.Errorf("read config %q: %w", path, err)
	}
	applyEnv(&cfg)
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func LoadFromFlags(args []string) (Config, error) {
	fs := flag.NewFlagSet("agentmesh", flag.ContinueOnError)
	configPath := fs.String("config", "agentmesh.yaml", "configuration file")
	listen := fs.String("listen", "", "listen address")
	downstream := fs.String("downstream", "", "downstream MCP URL")
	policy := fs.String("policy", "", "OPA/Rego policy path")
	version := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if *version {
		return Config{PolicyPath: Version}, nil
	}
	cfg, err := Load(*configPath)
	if err != nil {
		return Config{}, err
	}
	if *listen != "" {
		cfg.ListenAddr = *listen
	}
	if *downstream != "" {
		cfg.DownstreamURL = *downstream
	}
	if *policy != "" {
		cfg.PolicyPath = *policy
	}
	return cfg, cfg.Validate()
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.ListenAddr) == "" {
		return errors.New("listen address is required")
	}
	if strings.TrimSpace(c.DownstreamURL) == "" {
		return errors.New("downstream URL is required")
	}
	if strings.TrimSpace(c.PolicyPath) == "" {
		return errors.New("policy path is required")
	}
	if c.RateLimitPerMinute <= 0 || c.MaxRequestBodyBytes <= 0 || c.MaxResponseBodyBytes <= 0 {
		return errors.New("limits must be positive")
	}
	return nil
}

func (c Config) IdentitiesForStore() []*auth.AgentIdentity {
	result := make([]*auth.AgentIdentity, 0, len(c.Identities))
	for _, identity := range c.Identities {
		result = append(result, &auth.AgentIdentity{
			AgentID:       identity.AgentID,
			TenantID:      identity.TenantID,
			KeyHash:       identity.TokenHash,
			Status:        auth.AgentStatus(strings.ToUpper(identity.Status)),
			TrustScore:    identity.TrustScore,
			AllowedScopes: append([]string(nil), identity.AllowedScopes...),
			ExpiresAt:     identity.ExpiresAt,
		})
	}
	return result
}

func applyEnv(c *Config) {
	stringValue := func(key string, target *string) {
		if value, ok := os.LookupEnv(key); ok {
			*target = value
		}
	}
	intValue := func(key string, target *int) {
		if value, ok := os.LookupEnv(key); ok {
			if parsed, err := strconv.Atoi(value); err == nil {
				*target = parsed
			}
		}
	}
	durationValue := func(key string, target *time.Duration) {
		if value, ok := os.LookupEnv(key); ok {
			if parsed, err := time.ParseDuration(value); err == nil {
				*target = parsed
			}
		}
	}
	stringValue("AGENTMESH_LISTEN_ADDR", &c.ListenAddr)
	stringValue("AGENTMESH_DOWNSTREAM_URL", &c.DownstreamURL)
	stringValue("AGENTMESH_POLICY_PATH", &c.PolicyPath)
	intValue("AGENTMESH_RATE_LIMIT_PER_MINUTE", &c.RateLimitPerMinute)
	durationValue("AGENTMESH_DOWNSTREAM_TIMEOUT", &c.DownstreamTimeout)
	durationValue("AGENTMESH_READ_HEADER_TIMEOUT", &c.ReadHeaderTimeout)
	durationValue("AGENTMESH_READ_TIMEOUT", &c.ReadTimeout)
	durationValue("AGENTMESH_WRITE_TIMEOUT", &c.WriteTimeout)
	durationValue("AGENTMESH_IDLE_TIMEOUT", &c.IdleTimeout)
}
