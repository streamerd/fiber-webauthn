# Fiber WebAuthn Middleware

[![Release](https://img.shields.io/github/release/gofiber/webauthn.svg)](https://github.com/streamerd/fiber-webauthn/releases)
[![Discord](https://img.shields.io/discord/704680098577514527?style=flat&label=%F0%9F%92%AC%20discord&color=00ACD7)](https://gofiber.io/discord)
[![Go Reference](https://pkg.go.dev/badge/github.com/streamerd/fiber-webauthn.svg)](https://pkg.go.dev/github.com/streamerd/fiber-webauthn)

WebAuthn middleware for [Fiber](https://github.com/gofiber/fiber) that implements [Web Authentication API (WebAuthn)](https://www.w3.org/TR/webauthn-2/). This middleware enables passwordless authentication using biometrics, mobile devices, and FIDO2 security keys.

## 📦 Installation

```bash
go get -u github.com/streamerd/fiber-webauthn
```

## ⚡️ Quickstart

```go
package main

import (
    "github.com/gofiber/fiber/v2"
    "github.com/streamerd/fiber-webauthn"
)

func main() {
    app := fiber.New()

    // Initialize WebAuthn middleware
    webAuthnMiddleware := webauthn.New(webauthn.Config{
        RPDisplayName: "My Application",
        RPID:         "example.com",
        RPOrigins:    []string{"https://example.com"},
    })

    // Define your routes
    auth := app.Group("/auth/passkey")
    auth.Post("/register/begin", webAuthnMiddleware.BeginRegistration())
    auth.Post("/register/finish", webAuthnMiddleware.FinishRegistration())
    auth.Post("/login/begin", webAuthnMiddleware.BeginAuthentication())
    auth.Post("/login/finish", webAuthnMiddleware.FinishAuthentication())

    app.Listen(":3000")
}
```

## ⚙️ Configuration

| Property | Type | Description | Default |
|----------|------|-------------|----------|
| RPDisplayName | `string` | Human-readable name of your application | Required |
| RPID | `string` | Your application's domain name | Required |
| RPOrigins | `[]string` | Allowed origins (e.g., ["https://example.com"]) | Required |
| Timeout | `time.Duration` | Timeout for WebAuthn operations | `60 * time.Second` |
| AuthenticatorAttachment | `protocol.AuthenticatorAttachment` | Platform or Cross-platform authenticator | `""` |
| UserVerification | `protocol.UserVerificationRequirement` | User verification requirement | `"preferred"` |
| SessionCookieName | `string` | Name of the session cookie | `"webauthn_session"` |
| SessionCookiePath | `string` | Path of the session cookie | `"/"` |
| SessionCookieDomain | `string` | Domain of the session cookie | Same as RPID |
| SessionCookieSecure | `bool` | Whether the cookie is secure | `true` |
| SessionCookieHTTPOnly | `bool` | Whether the cookie is HTTP only | `true` |
| SessionCookieSameSite | `string` | SameSite attribute of the cookie | `"Strict"` |
| SessionTimeout | `time.Duration` | Session validity duration | `5 * time.Minute` |
| ResidentKey | `protocol.ResidentKeyRequirement` | Resident key requirement | `"preferred"` |
| AuthenticatorRequireResidentKey | `*bool` | Require resident key | `nil` |
| AuthenticatorUserVerification | `protocol.UserVerificationRequirement` | User verification requirement | `"preferred"` |
| AttestationPreference | `protocol.ConveyancePreference` | Attestation conveyance preference | `"none"` |
| AuthenticatorSelection | `*protocol.AuthenticatorSelection` | Authenticator selection criteria | `nil` |
| ExcludeCredentials | `[]protocol.CredentialDescriptor` | Credentials to exclude | `nil` |
| Extensions | `protocol.AuthenticationExtensions` | WebAuthn extensions | `nil` |
| CredentialStore | `CredentialStore` | Custom credential storage implementation | `nil` |
| SessionStore | `SessionStore` | Custom session storage implementation | In-memory store |
| Debug | `bool` | Enable debug logging | `false` |

## 🔍 API Endpoints

### Registration Flow

1. Begin Registration
```http
POST /auth/passkey/register/begin
Content-Type: application/json

{
    "userId": "user123",
    "username": "john_doe",     // optional
    "displayName": "John Doe"   // optional
}
```

Response:
```json
{
    "publicKey": {
        "challenge": "...",
        "rp": {
            "name": "My Application",
            "id": "example.com"
        },
        "user": {
            "id": "user123",
            "name": "john_doe",
            "displayName": "John Doe"
        },
        "pubKeyCredParams": [...],
        "timeout": 60000,
        "attestation": "none"
    }
}
```

2. Finish Registration
```http
POST /auth/passkey/register/finish
Content-Type: application/json

// Browser-generated credential response
```

Response:
```json
{
    "status": "success",
    "credential": {
        "id": "...",
        "type": "public-key",
        "aaguid": "...",
        "signCount": 0
    }
}
```

### Authentication Flow

1. Begin Authentication
```http
POST /auth/passkey/login/begin
Content-Type: application/json

{
    "userId": "user123"
}
```

2. Finish Authentication
```http
POST /auth/passkey/login/finish
Content-Type: application/json

// Browser-generated assertion response
```

Response:
```json
{
    "status": "success",
    "user": "user123"
}
```

## 🔐 Custom Storage

You can implement your own storage for credentials and sessions by implementing these interfaces:

```go
type CredentialStore interface {
    StoreCredential(userID string, cred *Credential) error
    GetCredential(credentialID []byte) (*Credential, error)
    GetCredentialsByUser(userID string) ([]*Credential, error)
    UpdateCredential(cred *Credential) error
}

type SessionStore interface {
    StoreSession(sessionID string, data *SessionData) error
    GetSession(sessionID string) (*SessionData, error)
    DeleteSession(sessionID string) error
}
```

## 📝 Custom Storage Examples

### MongoDB Implementation
```go
type MongoCredentialStore struct {
    collection *mongo.Collection
}

func NewMongoCredentialStore(collection *mongo.Collection) *MongoCredentialStore {
    return &MongoCredentialStore{collection: collection}
}

func (s *MongoCredentialStore) StoreCredential(userID string, cred *Credential) error {
    _, err := s.collection.InsertOne(context.Background(), struct {
        UserID    string    `bson:"userId"`
        Credential *Credential `bson:"credential"`
        CreatedAt time.Time `bson:"createdAt"`
    }{
        UserID:     userID,
        Credential: cred,
        CreatedAt:  time.Now(),
    })
    return err
}

func (s *MongoCredentialStore) GetCredentialsByUser(userID string) ([]*Credential, error) {
    cursor, err := s.collection.Find(context.Background(), bson.M{"userId": userID})
    if err != nil {
        return nil, err
    }
    defer cursor.Close(context.Background())

    var credentials []*Credential
    for cursor.Next(context.Background()) {
        var result struct {
            Credential *Credential `bson:"credential"`
        }
        if err := cursor.Decode(&result); err != nil {
            return nil, err
        }
        credentials = append(credentials, result.Credential)
    }
    return credentials, nil
}
```

### Redis Session Store
```go
type RedisSessionStore struct {
    client *redis.Client
}

func NewRedisSessionStore(client *redis.Client) *RedisSessionStore {
    return &RedisSessionStore{client: client}
}

func (s *RedisSessionStore) StoreSession(sessionID string, data *SessionData) error {
    jsonData, err := json.Marshal(data)
    if err != nil {
        return err
    }
    return s.client.Set(context.Background(), 
        "webauthn_session:"+sessionID, 
        jsonData, 
        time.Until(data.ExpiresAt),
    ).Err()
}

func (s *RedisSessionStore) GetSession(sessionID string) (*SessionData, error) {
    data, err := s.client.Get(context.Background(), "webauthn_session:"+sessionID).Bytes()
    if err != nil {
        return nil, err
    }
    
    var session SessionData
    if err := json.Unmarshal(data, &session); err != nil {
        return nil, err
    }
    return &session, nil
}
```

## 🌐 Browser Integration

### JavaScript Example
```javascript
async function registerPasskey() {
    // Start registration
    const startResp = await fetch('/auth/passkey/register/begin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            userId: 'user123',
            username: 'john_doe',
            displayName: 'John Doe'
        })
    });
    const options = await startResp.json();

    // Create credentials
    const credential = await navigator.credentials.create({
        publicKey: {
            ...options.publicKey,
            challenge: base64URLToBuffer(options.publicKey.challenge),
            user: {
                ...options.publicKey.user,
                id: base64URLToBuffer(options.publicKey.user.id),
            }
        }
    });

    // Complete registration
    const finishResp = await fetch('/auth/passkey/register/finish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            id: credential.id,
            rawId: bufferToBase64URL(credential.rawId),
            type: credential.type,
            response: {
                attestationObject: bufferToBase64URL(credential.response.attestationObject),
                clientDataJSON: bufferToBase64URL(credential.response.clientDataJSON)
            }
        })
    });
    return finishResp.json();
}

async function authenticateWithPasskey() {
    // Start authentication
    const startResp = await fetch('/auth/passkey/login/begin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: 'user123' })
    });
    const options = await startResp.json();

    // Get assertion
    const assertion = await navigator.credentials.get({
        publicKey: {
            ...options.publicKey,
            challenge: base64URLToBuffer(options.publicKey.challenge),
            allowCredentials: options.publicKey.allowCredentials.map(cred => ({
                ...cred,
                id: base64URLToBuffer(cred.id)
            }))
        }
    });

    // Complete authentication
    const finishResp = await fetch('/auth/passkey/login/finish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            id: assertion.id,
            rawId: bufferToBase64URL(assertion.rawId),
            type: assertion.type,
            response: {
                authenticatorData: bufferToBase64URL(assertion.response.authenticatorData),
                clientDataJSON: bufferToBase64URL(assertion.response.clientDataJSON),
                signature: bufferToBase64URL(assertion.response.signature),
                userHandle: bufferToBase64URL(assertion.response.userHandle)
            }
        })
    });
    return finishResp.json();
}

// Utility functions
function bufferToBase64URL(buffer) {
    const bytes = new Uint8Array(buffer);
    const str = String.fromCharCode.apply(null, bytes);
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64URLToBuffer(base64URL) {
    const base64 = base64URL.replace(/-/g, '+').replace(/_/g, '/');
    const padLen = (4 - (base64.length % 4)) % 4;
    const padded = base64 + '='.repeat(padLen);
    const binary = atob(padded);
    const buffer = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        buffer[i] = binary.charCodeAt(i);
    }
    return buffer.buffer;
}
```

## 🔍 Data Models

### WebAuthnUser
```go
// WebAuthnUser implements webauthn.User interface
type WebAuthnUser struct {
    ID          []byte                 `json:"id"`
    Name        string                 `json:"name"`
    DisplayName string                 `json:"displayName"`
    Credentials []webauthn.Credential  `json:"credentials,omitempty"`
}
```

### Credential
```go
type Credential struct {
    ID              []byte    `json:"id"`              // Raw credential ID
    PublicKey       []byte    `json:"publicKey"`       // Raw public key
    AttestationType string    `json:"attestationType"` // Type of attestation
    AAGUID          []byte    `json:"aaguid"`          // Authenticator AAGUID
    SignCount       uint32    `json:"signCount"`       // Signature counter
    CreatedAt       time.Time `json:"createdAt"`
    LastUsedAt      time.Time `json:"lastUsedAt"`
}
```

### SessionData
```go
type SessionData struct {
    UserID      string             `json:"userId"`
    Challenge   string             `json:"challenge"`
    SessionData webauthn.SessionData `json:"sessionData"`
    ExpiresAt   time.Time         `json:"expiresAt"`
}
```

## 📝 License

MIT License. See [LICENSE](LICENSE) for more details.
