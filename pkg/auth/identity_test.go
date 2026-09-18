package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name          string
		header        string
		expectedToken string
		expectedErr   error
	}{
		{
			name:          "Clean header",
			header:        "Bearer secret-key-123",
			expectedToken: "secret-key-123",
			expectedErr:   nil,
		},
		{
			name:          "Missing header",
			header:        "",
			expectedToken: "",
			expectedErr:   ErrMissingAuth,
		},
		{
			name:          "Malformed",
			header:        "secret-key-123",
			expectedToken: "",
			expectedErr:   ErrInvalidToken,
		},
		{
			name:          "Non-bearer scheme",
			header:        "Basic dXNlcjpwYXNz",
			expectedToken: "",
			expectedErr:   ErrInvalidToken,
		},
		{
			name:          "Whitespace handling",
			header:        "Bearer   key-with-spaces   ",
			expectedToken: "key-with-spaces",
			expectedErr:   nil,
		},
		{
			name:          "Empty token after prefix",
			header:        "Bearer   ",
			expectedToken: "",
			expectedErr:   ErrInvalidToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := ExtractBearerToken(tt.header)
			if token != tt.expectedToken {
				t.Errorf("Expected token %s, got %s", tt.expectedToken, token)
			}
			if err != tt.expectedErr {
				t.Errorf("Expected error %v, got %v", tt.expectedErr, err)
			}
		})
	}
}

func TestHashKey(t *testing.T) {
	rawKey := "agent-secret-key-456123-789456"

	hash1 := HashKey(rawKey)
	hash2 := HashKey(rawKey)

	if hash1 != hash2 {
		t.Errorf("hashes do not match")
	}

	if len(hash1) != 64 {
		t.Errorf("hash length is not 64 characters")
	}
}

func TestMemoryIdentityStore_Resolve(t *testing.T) {
	store := NewMemoryIdentityStore()

	rawKey := "agent-secret-key-456123-789456"
	keyHash := HashKey(rawKey)

	agent := &AgentIdentity{
		AgentID:    "agent-001",
		KeyHash:    keyHash,
		Status:     StatusActive,
		TrustScore: 95,
	}

	store.Set(agent)

	t.Run("Existing Key", func(t *testing.T) {
		ident, err := store.Resolve(context.Background(), keyHash)

		if err != nil {
			t.Fatalf("Resolve returned an error: %v", err)
		}
		if ident.AgentID != "agent-001" {
			t.Errorf("Expected agent ID agent-001, got %s", ident.AgentID)
		}
	})

	t.Run("Non-existent Key", func(t *testing.T) {
		_, err := store.Resolve(context.Background(), "unknown-nonexistent-hash")

		if !errors.Is(err, ErrInvalidToken) {
			t.Errorf("Expected ErrInvalidToken, got %v", err)
		}
	})
}

func TestValidateIdentity(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name        string
		identity    *AgentIdentity
		expectedErr error
	}{
		{
			name: "Valid Active Identity",
			identity: &AgentIdentity{
				AgentID:    "agent-001",
				KeyHash:    "key-hash-123",
				Status:     StatusActive,
				TrustScore: 95,
			},
			expectedErr: nil,
		},
		{
			name: "Suspended Identity",
			identity: &AgentIdentity{
				AgentID:    "agent-002",
				KeyHash:    "key-hash-456",
				Status:     StatusSuspended,
				TrustScore: 80,
			},
			expectedErr: ErrAgentInactive,
		},
		{
			name: "Expired Token",
			identity: &AgentIdentity{
				AgentID:    "agent-expired",
				KeyHash:    "key-hash-789",
				Status:     StatusActive,
				TrustScore: 85,
				ExpiresAt:  now.Add(-1 * time.Hour),
			},
			expectedErr: ErrAgentExpired,
		},
		{
			name: "Trust Score Out of Bounds (Too High)",
			identity: &AgentIdentity{
				AgentID:    "agent-high-score",
				KeyHash:    "key-hash-999",
				Status:     StatusActive,
				TrustScore: 150,
				ExpiresAt:  now.Add(1 * time.Hour),
			},
			expectedErr: errors.New("Trust score out of bound"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIdentity(tt.identity, now)

			if tt.expectedErr != nil {
				if err == nil {
					t.Fatalf("Expected error, got nil")
				}
				// Error message strings දෙක සමානදැයි බැලීම
				if err.Error() != tt.expectedErr.Error() {
					t.Errorf("Expected error message %q, got %q", tt.expectedErr.Error(), err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("Expected nil error, got %v", err)
				}
			}
		})
	}
}
