package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"
	"sync"
)

type AgentStatus string

const (
	StatusActive  AgentStatus = "ACTIVE"
	StatusSuspended AgentStatus = "SUSPENDED"
	StatusRevoked AgentStatus = "REVOKED"
)

var (
	ErrMissingAuth = errors.New("missing authentication information")
	ErrInvalidToken = errors.New("invalid or malformed token")
	ErrAgentInactive = errors.New("agent is not active or suspended")
    ErrAgentExpired = errors.New("agent's token has expired")
)

type AgentIdentity struct {
	AgentID string      `json:"agent_id"`
	TenantID string      `json:"tenant_id"`
	KeyHash string       `json:"key_hash"`
	Status AgentStatus  `json:"status"`
	TrustScore int 	   `json:"trust_score"`
	AllowedScopes []string   `json:"allowed_scopes"`
	RateLimitTier string      `json:"rate_limit_tier"`
	ExpiresAt time.Time   `json:"expires_at"`
}

func ExtractBearerToken(authHeader string) (string, error) {
	trimed := strings.TrimSpace(authHeader)
	if trimed == "" {
		return "", ErrMissingAuth
	}

	if !strings.HasPrefix(trimed, "Bearer "){
		return "", ErrInvalidToken
	}

	token := strings.TrimPrefix(trimed, "Bearer ")
	token = strings.TrimSpace(token)
	if token == "" {
		return "", ErrInvalidToken
	}
	return token, nil
}

func HashKey(rawKey string) string {
	hash := sha256.Sum256([]byte(rawKey))
	hashHex := hex.EncodeToString(hash[:])

	return hashHex
}

type IdentityResolver interface {
	Resolve(ctx context.Context, keyHash string) (*AgentIdentity, error)
}

type MemoryIdentityStore struct {
	mu sync.RWMutex
	identities map[string]*AgentIdentity
}

func NewMemoryIdentityStore() *MemoryIdentityStore {
	return &MemoryIdentityStore{
		identities: make(map[string]*AgentIdentity),
	}
}

func (s *MemoryIdentityStore) Set(identity *AgentIdentity){

	if identity == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.identities[identity.KeyHash] = identity
}

func (s *MemoryIdentityStore) Resolve(ctx context.Context, keyHash string) (*AgentIdentity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	identity, exists := s.identities[keyHash]

	if !exists {
		return nil, ErrInvalidToken
	}

	return identity, nil

}

func ValidateIdentity(identity *AgentIdentity, now time.Time) error {
	if identity == nil {
		return ErrInvalidToken
	}

	if identity.Status != StatusActive {
		return ErrAgentInactive
	}

	if !identity.ExpiresAt.IsZero() && now.After(identity.ExpiresAt) {
		return ErrAgentExpired
	}

	if identity.TrustScore < 0 || identity.TrustScore > 100 {
		return errors.New("Trust score out of bound")
	}

	return nil
}