package webauthn

import (
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/assert"
)

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr error
	}{
		{
			name: "valid config",
			config: Config{
				RPDisplayName: "Test App",
				RPID:          "example.com",
				RPOrigins:     []string{"https://example.com"},
			},
			wantErr: nil,
		},
		{
			name: "missing display name",
			config: Config{
				RPID:      "example.com",
				RPOrigins: []string{"https://example.com"},
			},
			wantErr: ErrMissingRPDisplayName,
		},
		{
			name: "missing RPID",
			config: Config{
				RPDisplayName: "Test App",
				RPOrigins:     []string{"https://example.com"},
			},
			wantErr: ErrMissingRPID,
		},
		{
			name: "missing origins",
			config: Config{
				RPDisplayName: "Test App",
				RPID:          "example.com",
			},
			wantErr: ErrMissingRPOrigins,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.validate()
			assert.Equal(t, tt.wantErr, err)
		})
	}
}

func TestConfigDefaults(t *testing.T) {
	config := Config{
		RPDisplayName: "Test App",
		RPID:          "example.com",
		RPOrigins:     []string{"https://example.com"},
	}

	config.setDefaults()

	assert.Equal(t, 60*time.Second, config.Timeout)
	assert.Equal(t, protocol.VerificationPreferred, config.UserVerification)
	assert.Equal(t, "webauthn_session", config.SessionCookieName)
	assert.Equal(t, "/", config.SessionCookiePath)
	assert.Equal(t, "example.com", config.SessionCookieDomain)
	assert.Equal(t, true, config.SessionCookieSecure)
	assert.Equal(t, true, config.SessionCookieHTTPOnly)
	assert.Equal(t, "Strict", config.SessionCookieSameSite)
	assert.Equal(t, 5*time.Minute, config.SessionTimeout)
	assert.Equal(t, protocol.ResidentKeyPreferred, config.ResidentKey)
	assert.Equal(t, protocol.PreferNoAttestation, config.AttestationPreference)
	assert.NotNil(t, config.SessionStore)
}
