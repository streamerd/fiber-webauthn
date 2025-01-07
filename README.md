# Fiber WebAuthn Middleware

# Fiber WebAuthn Middleware

[![Release](https://img.shields.io/github/release/gofiber/webauthn.svg)](https://github.com/streamerd/fiber-webauthn/releases)
[![Discord](https://img.shields.io/discord/704680098577514527?style=flat&label=%F0%9F%92%AC%20discord&color=00ACD7)](https://gofiber.io/discord)
[![Go Reference](https://pkg.go.dev/badge/github.com/streamerd/fiber-webauthn.svg)](https://pkg.go.dev/github.com/streamerd/fiber-webauthn)
[![FIDO2 Certified](https://img.shields.io/badge/FIDO2-Certified-yellow)](https://fidoalliance.org/fido2/)



WebAuthn middleware for [Fiber](https://github.com/gofiber/fiber) that implements [Web Authentication API (WebAuthn)](https://www.w3.org/TR/webauthn-2/), using [go-webauthn](https://github.com/go-webauthn/webauthn). This middleware enables passwordless authentication using biometrics, mobile devices, and FIDO2 security keys aka [Passkeys](https://fidoalliance.org/passkeys/).


## 📦 Installation

```bash
go get -u github.com/streamerd/fiber-webauthn
```

## ⚡️ Quickstart

```go
package main

import (
    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/template/html/v2"
    "github.com/streamerd/fiber-webauthn"
)

func main() {
    // Initialize template engine
    engine := html.New("./views", ".html")

    // Initialize Fiber
    app := fiber.New(fiber.Config{
        Views: engine,
        DisableStartupMessage: true,
    })

    // Add redirect middleware for WebAuthn security
    app.Use(func(c *fiber.Ctx) error {
        if c.Hostname() == "127.0.0.1" {
            originalURL := c.OriginalURL()
            if originalURL == "" {
                originalURL = "/"
            }
            return c.Redirect("http://localhost:3000" + originalURL)
        }
        return c.Next()
    })

    // Initialize WebAuthn middleware
    webAuthnMiddleware := webauthn.New(webauthn.Config{
        RPDisplayName: "WebAuthn Example",
        RPID:         "localhost",
        RPOrigins:    []string{"http://localhost:3000"},
    })

    // Define your routes
    auth := app.Group("/auth/passkey")
    auth.Post("/register/begin", webAuthnMiddleware.BeginRegistration())
    auth.Post("/register/finish", webAuthnMiddleware.FinishRegistration())
    auth.Post("/login/begin", webAuthnMiddleware.BeginAuthentication())
    auth.Post("/login/finish", webAuthnMiddleware.FinishAuthentication())

    log.Fatal(app.Listen("localhost:3000"))
}
```

## ⚙️ Configuration

| Property | Type | Description | Default | Required |
|----------|------|-------------|----------|----------|
| RPDisplayName | `string` | Human-readable name of your application | - | Yes |
| RPID | `string` | Your application's domain name (e.g., "localhost") | - | Yes |
| RPOrigins | `[]string` | Allowed origins (e.g., ["http://localhost:3000"]) | - | Yes |
| CredentialStore | `CredentialStore` | Custom credential storage implementation | In-memory store | No |
| SessionStore | `SessionStore` | Custom session storage implementation | In-memory store | No |
| Timeout | `time.Duration` | Timeout for WebAuthn operations | `60 * time.Second` | No |
| AuthenticatorAttachment | `protocol.AuthenticatorAttachment` | Platform or Cross-platform authenticator | `""` | No |
| UserVerification | `protocol.UserVerificationRequirement` | User verification requirement | `"preferred"` | No |
| SessionCookieName | `string` | Name of the session cookie | `"webauthn_session"` | No |
| SessionCookiePath | `string` | Path of the session cookie | `"/"` | No |
| SessionCookieDomain | `string` | Domain of the session cookie | Same as RPID | No |
| SessionCookieSecure | `bool` | Whether the cookie is secure | `true` | No |
| SessionCookieHTTPOnly | `bool` | Whether the cookie is HTTP only | `true` | No |
| SessionCookieSameSite | `string` | SameSite attribute of the cookie | `"Strict"` | No |
| SessionTimeout | `time.Duration` | Session validity duration | `5 * time.Minute` | No |
| ResidentKey | `protocol.ResidentKeyRequirement` | Resident key requirement | `"preferred"` | No |
| AuthenticatorRequireResidentKey | `*bool` | Require resident key | `nil` | No |
| AuthenticatorUserVerification | `protocol.UserVerificationRequirement` | User verification requirement | `"preferred"` | No |
| AttestationPreference | `protocol.ConveyancePreference` | Attestation conveyance preference | `"none"` | No |
| AuthenticatorSelection | `*protocol.AuthenticatorSelection` | Authenticator selection criteria | `nil` | No |
| ExcludeCredentials | `[]protocol.CredentialDescriptor` | Credentials to exclude | `nil` | No |
| Extensions | `protocol.AuthenticationExtensions` | WebAuthn extensions | `nil` | No |
| Debug | `bool` | Enable debug logging | `false` | No |


## 🔍 Data Models

### WebAuthnUser
```go
type WebAuthnUser struct {
    ID          []byte
    Name        string
    DisplayName string
    Credentials []webauthn.Credential
}
```

### Credential
```go
type Credential struct {
    ID              []byte
    PublicKey       []byte
    AttestationType string
    AAGUID          []byte
    SignCount       uint32
    CreatedAt       time.Time
    LastUsedAt      time.Time
}
```


## 🔍 API Endpoints

### Registration Flow

1. Begin Registration
```http
POST /auth/passkey/register/begin
Content-Type: application/json

{
    "userId": "user123",
    "username": "john_doe",
    "displayName": "John Doe"
}
```

2. Finish Registration
```http
POST /auth/passkey/register/finish
Content-Type: application/json
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
```

## 📝 Important Notes

1. WebAuthn requires either HTTPS or localhost for security
2. When using localhost, ensure:
   - RPID is set to "localhost"
   - RPOrigins includes your full origin (e.g., "http://localhost:3000")
   - Redirect 127.0.0.1 to localhost for proper operation
3. Include `credentials: 'include'` in fetch requests
4. Use proper MIME types in requests/responses


## 🚀 Example Usage

See the [example](example) directory for a complete working example including:
- User registration and authentication
- Credential storage using SQLite
- HTML templates and JavaScript integration

## 📄 License

MIT License. See [LICENSE](LICENSE) for more details.
