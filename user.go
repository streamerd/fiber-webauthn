package webauthn

import (
	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthnUser implements webauthn.User interface
type WebAuthnUser struct {
	id          []byte
	name        string
	displayName string
	credentials []webauthn.Credential
}

func NewWebAuthnUser(id string, name string, displayName string) *WebAuthnUser {
	return &WebAuthnUser{
		id:          []byte(id),
		name:        name,
		displayName: displayName,
	}
}

// Implementation of webauthn.User interface
func (u *WebAuthnUser) WebAuthnID() []byte                         { return u.id }
func (u *WebAuthnUser) WebAuthnName() string                       { return u.name }
func (u *WebAuthnUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }
func (u *WebAuthnUser) WebAuthnIcon() string                       { return "" }
