package webauthn

import (
	"bytes"
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gofiber/fiber/v2"
)

type Middleware struct {
	config      Config
	webAuthn    *webauthn.WebAuthn
	sessions    SessionStore
	credentials CredentialStore
}

// New creates a new WebAuthn middleware instance
func New(config Config) *Middleware {
	// Set default values
	config.setDefaults()

	// Validate configuration
	if err := config.validate(); err != nil {
		panic(err)
	}

	// Initialize WebAuthn with config
	w, err := webauthn.New(&webauthn.Config{
		RPDisplayName: config.RPDisplayName,
		RPID:          config.RPID,
		RPOrigins:     config.RPOrigins,
	})
	if err != nil {
		panic(err)
	}

	return &Middleware{
		config:      config,
		webAuthn:    w,
		sessions:    NewDefaultSessionStore(),
		credentials: config.CredentialStore,
	}
}

// BeginRegistration returns a handler for starting the registration process
func (m *Middleware) BeginRegistration() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get user info from request
		var req struct {
			UserID      string `json:"userId"`
			Username    string `json:"username,omitempty"`
			DisplayName string `json:"displayName,omitempty"`
		}

		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid request body",
			})
		}

		// Create WebAuthn user
		user := NewWebAuthnUser(req.UserID, req.Username, req.DisplayName)

		// Get existing credentials
		existingCreds, err := m.credentials.GetCredentialsByUser(req.UserID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to get existing credentials",
			})
		}

		// Convert to WebAuthn credentials
		var webAuthnCreds []webauthn.Credential
		for _, cred := range existingCreds {
			webAuthnCreds = append(webAuthnCreds, webauthn.Credential{
				ID:              cred.ID,
				PublicKey:       cred.PublicKey,
				AttestationType: cred.AttestationType,
				Transport:       nil,
			})
		}
		user.credentials = webAuthnCreds

		// Create registration options
		options, sessionData, err := m.webAuthn.BeginRegistration(
			user,
			webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
				AuthenticatorAttachment: m.config.AuthenticatorAttachment,
				UserVerification:        m.config.UserVerification,
			}),
		)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		// Store session data
		sessionID := generateSessionID()
		err = m.sessions.StoreSession(sessionID, &SessionData{
			UserID:      req.UserID,
			Challenge:   sessionData.Challenge,
			SessionData: *sessionData,
			ExpiresAt:   time.Now().Add(m.config.Timeout),
		})
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to store session",
			})
		}

		// Set session cookie
		c.Cookie(&fiber.Cookie{
			Name:     "webauthn_session",
			Value:    sessionID,
			HTTPOnly: true,
			Secure:   true,
			SameSite: "Strict",
			MaxAge:   int(m.config.Timeout.Seconds()),
		})

		return c.JSON(options)
	}
}

// FinishRegistration completes the registration ceremony
func (m *Middleware) FinishRegistration() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get session from cookie
		sessionID := c.Cookies("webauthn_session")
		if sessionID == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "no session found",
			})
		}

		// Get session data
		session, err := m.sessions.GetSession(sessionID)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		// Create WebAuthn user
		user := NewWebAuthnUser(session.UserID, "", "") // Names not needed for finish

		// For registration
		httpReq := &http.Request{
			Method: "POST",
			Body:   io.NopCloser(bytes.NewReader(c.Body())),
		}
		credential, err := m.webAuthn.FinishRegistration(user, session.SessionData, httpReq)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		// Store the credential
		newCred := &Credential{
			ID:              credential.ID,
			PublicKey:       credential.PublicKey,
			AttestationType: credential.AttestationType,
			AAGUID:          credential.Authenticator.AAGUID,
			SignCount:       credential.Authenticator.SignCount,
			CreatedAt:       time.Now(),
			LastUsedAt:      time.Now(),
		}

		if err := m.credentials.StoreCredential(session.UserID, newCred); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to store credential",
			})
		}

		// Clean up session
		if err := m.sessions.DeleteSession(sessionID); err != nil {
			// Log error but don't fail the request
			log.Printf("Failed to delete session: %v", err)
		}

		// Remove session cookie
		c.Cookie(&fiber.Cookie{
			Name:     "webauthn_session",
			Value:    "",
			Expires:  time.Now().Add(-time.Hour),
			HTTPOnly: true,
			Secure:   true,
			SameSite: "Strict",
		})

		return c.JSON(fiber.Map{
			"status": "success",
			"credential": fiber.Map{
				"id":        base64.URLEncoding.EncodeToString(credential.ID),
				"type":      "public-key",
				"aaguid":    base64.URLEncoding.EncodeToString(credential.Authenticator.AAGUID),
				"signCount": credential.Authenticator.SignCount,
			},
		})
	}
}

// BeginAuthentication initiates the authentication ceremony
func (m *Middleware) BeginAuthentication() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get user info from request
		var req struct {
			UserID string `json:"userId"`
		}

		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid request body",
			})
		}

		// Get user's credentials
		creds, err := m.credentials.GetCredentialsByUser(req.UserID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to get user credentials",
			})
		}

		if len(creds) == 0 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "no credentials found for user",
			})
		}

		// Create WebAuthn user
		user := NewWebAuthnUser(req.UserID, "", "")

		// Convert to WebAuthn credentials
		var webAuthnCreds []webauthn.Credential
		for _, cred := range creds {
			webAuthnCreds = append(webAuthnCreds, webauthn.Credential{
				ID:              cred.ID,
				PublicKey:       cred.PublicKey,
				AttestationType: cred.AttestationType,
				Transport:       nil,
			})
		}
		user.credentials = webAuthnCreds

		// Begin authentication
		options, sessionData, err := m.webAuthn.BeginLogin(user)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		// Store session data
		sessionID := generateSessionID()
		err = m.sessions.StoreSession(sessionID, &SessionData{
			UserID:      req.UserID,
			Challenge:   sessionData.Challenge,
			SessionData: *sessionData,
			ExpiresAt:   time.Now().Add(m.config.Timeout),
		})
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to store session",
			})
		}

		// Set session cookie
		c.Cookie(&fiber.Cookie{
			Name:     "webauthn_session",
			Value:    sessionID,
			HTTPOnly: true,
			Secure:   true,
			SameSite: "Strict",
			MaxAge:   int(m.config.Timeout.Seconds()),
		})

		return c.JSON(options)
	}
}

// FinishAuthentication completes the authentication ceremony
func (m *Middleware) FinishAuthentication() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get session from cookie
		sessionID := c.Cookies("webauthn_session")
		if sessionID == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "no session found",
			})
		}

		// Get session data
		session, err := m.sessions.GetSession(sessionID)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		// Create WebAuthn user
		user := NewWebAuthnUser(session.UserID, "", "")

		// Get user's credentials
		creds, err := m.credentials.GetCredentialsByUser(session.UserID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to get user credentials",
			})
		}

		// Convert to WebAuthn credentials
		var webAuthnCreds []webauthn.Credential
		for _, cred := range creds {
			webAuthnCreds = append(webAuthnCreds, webauthn.Credential{
				ID:              cred.ID,
				PublicKey:       cred.PublicKey,
				AttestationType: cred.AttestationType,
				Transport:       nil,
			})
		}
		user.credentials = webAuthnCreds

		// For authentication
		httpReq := &http.Request{
			Method: "POST",
			Body:   io.NopCloser(bytes.NewReader(c.Body())),
		}
		credential, err := m.webAuthn.FinishLogin(user, session.SessionData, httpReq)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		// Update credential sign count
		for _, cred := range creds {
			if bytes.Equal(cred.ID, credential.ID) {
				cred.SignCount = credential.Authenticator.SignCount
				cred.LastUsedAt = time.Now()
				if err := m.credentials.UpdateCredential(cred); err != nil {
					log.Printf("Failed to update credential: %v", err)
				}
				break
			}
		}

		// Clean up session
		if err := m.sessions.DeleteSession(sessionID); err != nil {
			log.Printf("Failed to delete session: %v", err)
		}

		// Remove session cookie
		c.Cookie(&fiber.Cookie{
			Name:     "webauthn_session",
			Value:    "",
			Expires:  time.Now().Add(-time.Hour),
			HTTPOnly: true,
			Secure:   true,
			SameSite: "Strict",
		})

		return c.JSON(fiber.Map{
			"status": "success",
			"user":   session.UserID,
		})
	}
}

// Similar handlers for FinishRegistration, BeginAuthentication, and FinishAuthentication...
