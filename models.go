package webauthn

import (
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// Credential represents a WebAuthn credential
type Credential struct {
	ID              []byte    `json:"id"`              // Raw credential ID
	PublicKey       []byte    `json:"publicKey"`       // Raw public key
	AttestationType string    `json:"attestationType"` // Type of attestation (e.g., "none", "fido-u2f")
	AAGUID          []byte    `json:"aaguid"`          // Authenticator attestation GUID
	SignCount       uint32    `json:"signCount"`       // Signature counter
	CreatedAt       time.Time `json:"createdAt"`
	LastUsedAt      time.Time `json:"lastUsedAt"`
}

// CredentialStore defines the interface for storing and retrieving credentials
type CredentialStore interface {
	// StoreCredential saves a new credential
	StoreCredential(userID string, cred *Credential) error

	// GetCredential retrieves a credential by ID
	GetCredential(credentialID []byte) (*Credential, error)

	// GetCredentialsByUser retrieves all credentials for a user
	GetCredentialsByUser(userID string) ([]*Credential, error)

	// UpdateCredential updates an existing credential
	UpdateCredential(cred *Credential) error
}

// SessionData represents the temporary session data for WebAuthn ceremonies
type SessionData struct {
	UserID      string
	Challenge   string
	SessionData webauthn.SessionData
	ExpiresAt   time.Time
}

// SessionStore defines the interface for managing WebAuthn sessions
type SessionStore interface {
	// StoreSession saves a new session
	StoreSession(sessionID string, data *SessionData) error

	// GetSession retrieves a session by ID
	GetSession(sessionID string) (*SessionData, error)

	// DeleteSession removes a session
	DeleteSession(sessionID string) error
}
