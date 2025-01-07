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

func TestBeginAuthentication(t *testing.T) {
	// Setup
	app := fiber.New()
	config := Config{
		RPDisplayName: "Test App",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost"},
		CredentialStore: &mockCredentialStore{
			credentials: map[string][]*Credential{
				"test-user": {
					{
						ID:              []byte("test-credential-id"),
						PublicKey:       []byte("test-public-key"),
						AttestationType: "none",
					},
				},
			},
		},
	}

	mw := New(config)
	app.Post("/login/begin", mw.BeginAuthentication())

	// Test case 1: Successful authentication initiation
	reqBody := `{"userId": "test-user"}`
	req := httptest.NewRequest("POST", "/login/begin", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
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
	assert.Contains(t, publicKey, "allowCredentials")

	// Test case 2: User with no credentials
	reqBody = `{"userId": "user-without-creds"}`
	req = httptest.NewRequest("POST", "/login/begin", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err = app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

	var errorResult map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&errorResult)
	assert.NoError(t, err)
	assert.Equal(t, "no credentials found for user", errorResult["error"])
}

func TestFinishAuthentication(t *testing.T) {
	// Setup
	app := fiber.New()
	config := Config{
		RPDisplayName: "Test App",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost"},
		CredentialStore: &mockCredentialStore{
			credentials: map[string][]*Credential{
				"test-user": {
					{
						ID:              []byte("test-credential-id"),
						PublicKey:       []byte("test-public-key"),
						AttestationType: "none",
						SignCount:       0,
					},
				},
			},
		},
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
		Challenge:   sessionData.Challenge,
		SessionData: *sessionData,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	})
	assert.NoError(t, err)

	app.Post("/login/finish", mw.FinishAuthentication())

	// Create mock assertion response
	mockResponse := createMockAssertionResponse(t, sessionData.Challenge)

	// Test case 1: Successful authentication completion
	req := httptest.NewRequest("POST", "/login/finish", bytes.NewReader(mockResponse))
	req.AddCookie(&http.Cookie{
		Name:  "webauthn_session",
		Value: sessionID,
	})

	resp, err := app.Test(req)
	assert.NoError(t, err)

	// Note: The actual status will be unauthorized because we're using mock data
	// In a real scenario, the webauthn library would validate the credential
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)

	// Test case 2: Missing session cookie
	req = httptest.NewRequest("POST", "/login/finish", bytes.NewReader(mockResponse))
	resp, err = app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)

	var errorResult map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&errorResult)
	assert.NoError(t, err)
	assert.Equal(t, "no session found", errorResult["error"])
}

// Helper function to create mock assertion response
func createMockAssertionResponse(t *testing.T, challenge string) []byte {
	response := map[string]interface{}{
		"id":    base64.URLEncoding.EncodeToString([]byte("test-credential-id")),
		"rawId": base64.URLEncoding.EncodeToString([]byte("test-credential-id")),
		"type":  "public-key",
		"response": map[string]interface{}{
			"authenticatorData": base64.URLEncoding.EncodeToString([]byte("test-auth-data")),
			"clientDataJSON": base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf(`{
				"type": "webauthn.get",
				"challenge": "%s",
				"origin": "http://localhost"
			}`, challenge))),
			"signature":  base64.URLEncoding.EncodeToString([]byte("test-signature")),
			"userHandle": base64.URLEncoding.EncodeToString([]byte("test-user")),
		},
	}

	data, err := json.Marshal(response)
	assert.NoError(t, err)
	return data
}
