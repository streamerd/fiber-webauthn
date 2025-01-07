package webauthn

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// DefaultSessionStore provides an in-memory implementation of SessionStore
type DefaultSessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*SessionData
}

func NewDefaultSessionStore() SessionStore {
	return &DefaultSessionStore{
		sessions: make(map[string]*SessionData),
	}
}

func (s *DefaultSessionStore) StoreSession(sessionID string, data *SessionData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sessionID] = data
	return nil
}

func (s *DefaultSessionStore) GetSession(sessionID string) (*SessionData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return nil, errors.New("session not found")
	}

	if time.Now().After(session.ExpiresAt) {
		delete(s.sessions, sessionID)
		return nil, errors.New("session expired")
	}

	return session, nil
}

func (s *DefaultSessionStore) DeleteSession(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
	return nil
}

// generateSessionID creates a random session ID
func generateSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
