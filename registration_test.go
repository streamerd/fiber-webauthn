package webauthn

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
)

func TestBeginRegistration(t *testing.T) {
	// Setup
	app := fiber.New()
	config := Config{
		RPDisplayName: "Test App",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost"},
	}

	mw := New(config)

	app.Post("/register/begin", mw.BeginRegistration("test-user", "testuser", "Test User"))

	// Test case 1: Successful registration initiation
	req := httptest.NewRequest("POST", "/register/begin", nil)
	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	assert.NoError(t, err)

	// Verify response contains required fields
	assert.Contains(t, result, "publicKey")
	publicKey := result["publicKey"].(map[string]interface{})
	assert.Contains(t, publicKey, "challenge")
	assert.Contains(t, publicKey, "rp")
	assert.Contains(t, publicKey, "user")
}

func TestFinishRegistration(t *testing.T) {
	// Setup
	app := fiber.New()
	config := Config{
		RPDisplayName:   "Test App",
		RPID:            "localhost",
		RPOrigins:       []string{"http://localhost"},
		CredentialStore: &mockCredentialStore{}, // Add mock store
	}

	mw := New(config)

	// Store test session
	sessionID := "test-session"
	sessionData := &webauthn.SessionData{
		Challenge: "test-challenge",
		UserID:    []byte("test-user"),
	}

	err := mw.sessions.StoreSession(sessionID, &SessionData{
		UserID:      "test-user",
		SessionData: *sessionData,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	})
	assert.NoError(t, err)

	app.Post("/register/finish", mw.FinishRegistration())

	// Create mock attestation response
	mockResponse := createMockAttestationResponse(t, sessionData.Challenge)

	// Test case 1: Successful registration completion
	req := httptest.NewRequest("POST", "/register/finish", bytes.NewReader(mockResponse))
	req.AddCookie(&http.Cookie{
		Name:  "webauthn_session",
		Value: sessionID,
	})

	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	assert.NoError(t, err)

	// Verify response structure
	assert.Equal(t, "success", result["status"])
	assert.Contains(t, result, "credential")
}

// Mock credential store for testing
type mockCredentialStore struct {
	credentials map[string][]*Credential
}

func (m *mockCredentialStore) StoreCredential(userID string, cred *Credential) error {
	if m.credentials == nil {
		m.credentials = make(map[string][]*Credential)
	}
	m.credentials[userID] = append(m.credentials[userID], cred)
	return nil
}

func (m *mockCredentialStore) GetCredential(credentialID []byte) (*Credential, error) {
	// Implementation for testing
	return nil, nil
}

func (m *mockCredentialStore) GetCredentialsByUser(userID string) ([]*Credential, error) {
	return m.credentials[userID], nil
}

func (m *mockCredentialStore) UpdateCredential(cred *Credential) error {
	return nil
}

// Helper function to create mock attestation response
func createMockAttestationResponse(t *testing.T, challenge string) []byte {
	// Create a minimal mock response
	// In real tests, this would be more complete
	response := map[string]interface{}{
		"id":    base64.URLEncoding.EncodeToString([]byte("test-credential-id")),
		"rawId": base64.URLEncoding.EncodeToString([]byte("test-credential-id")),
		"type":  "public-key",
		"response": map[string]interface{}{
			"attestationObject": base64.URLEncoding.EncodeToString([]byte("test-attestation")),
			"clientDataJSON": base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf(`{
				"type": "webauthn.create",
				"challenge": "%s",
				"origin": "http://localhost"
			}`, challenge))),
		},
	}

	data, err := json.Marshal(response)
	assert.NoError(t, err)
	return data
}
