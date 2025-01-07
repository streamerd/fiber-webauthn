package webauthn

import (
	"time"

	"github.com/go-webauthn/webauthn/protocol"
)

// Config represents the configuration for the WebAuthn middleware
type Config struct {
	// Required fields
	RPDisplayName string   // Human-readable name of your application
	RPID          string   // Your application's domain name
	RPOrigins     []string // Allowed origins (e.g., ["https://example.com"])

	// Optional fields
	Timeout                 time.Duration                        // Default: 60 seconds
	AuthenticatorAttachment protocol.AuthenticatorAttachment     // Platform or Cross-platform
	UserVerification        protocol.UserVerificationRequirement // Required, Preferred, or Discouraged

	// Session configuration
	SessionCookieName     string        // Default: "webauthn_session"
	SessionCookiePath     string        // Default: "/"
	SessionCookieDomain   string        // Default: same as RPID
	SessionCookieSecure   bool          // Default: true
	SessionCookieHTTPOnly bool          // Default: true
	SessionCookieSameSite string        // Default: "Strict"
	SessionTimeout        time.Duration // Default: 5 minutes

	// Authenticator configuration
	ResidentKey                     protocol.ResidentKeyRequirement      // Default: "preferred"
	AuthenticatorRequireResidentKey *bool                                // Default: nil (optional)
	AuthenticatorUserVerification   protocol.UserVerificationRequirement // Default: Preferred

	// Attestation configuration
	AttestationPreference  protocol.ConveyancePreference    // Default: protocol.PreferNoAttestation
	AuthenticatorSelection *protocol.AuthenticatorSelection // Default: nil (optional)

	// Credential configuration
	ExcludeCredentials []protocol.CredentialDescriptor   // Default: nil (optional)
	Extensions         protocol.AuthenticationExtensions // Default: nil (optional)

	// Custom handlers
	CredentialStore CredentialStore // Optional: Custom credential store
	SessionStore    SessionStore    // Optional: Custom session store

	// Debug options
	Debug bool // Default: false
}

// ConfigDefault is the default config
var ConfigDefault = Config{
	Timeout:               60 * time.Second,
	UserVerification:      protocol.VerificationPreferred,
	SessionCookieName:     "webauthn_session",
	SessionCookiePath:     "/",
	SessionCookieSecure:   true,
	SessionCookieHTTPOnly: true,
	SessionCookieSameSite: "Strict",
	SessionTimeout:        5 * time.Minute,
	ResidentKey:           protocol.ResidentKeyRequirement("preferred"),
	AttestationPreference: protocol.PreferNoAttestation,
	Debug:                 false,
}

// Helper method to set default values
func (c *Config) setDefaults() {
	if c.Timeout == 0 {
		c.Timeout = ConfigDefault.Timeout
	}
	if c.UserVerification == "" {
		c.UserVerification = ConfigDefault.UserVerification
	}
	if c.SessionCookieName == "" {
		c.SessionCookieName = ConfigDefault.SessionCookieName
	}
	if c.SessionCookiePath == "" {
		c.SessionCookiePath = ConfigDefault.SessionCookiePath
	}
	if c.SessionTimeout == 0 {
		c.SessionTimeout = ConfigDefault.SessionTimeout
	}
	if c.SessionCookieDomain == "" {
		c.SessionCookieDomain = c.RPID
	}
	if c.ResidentKey == "" {
		c.ResidentKey = ConfigDefault.ResidentKey
	}
	if c.AttestationPreference == "" {
		c.AttestationPreference = ConfigDefault.AttestationPreference
	}
	if c.SessionStore == nil {
		c.SessionStore = NewDefaultSessionStore()
	}
}

// Helper method to validate configuration
func (c *Config) validate() error {
	if c.RPDisplayName == "" {
		return ErrMissingRPDisplayName
	}
	if c.RPID == "" {
		return ErrMissingRPID
	}
	if len(c.RPOrigins) == 0 {
		return ErrMissingRPOrigins
	}
	return nil
}
