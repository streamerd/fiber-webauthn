package store

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
	"github.com/streamerd/fiber-webauthn"
)

type SQLiteStore struct {
	db *sql.DB
}

func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	// Create tables if they don't exist
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS credentials (
			id BLOB PRIMARY KEY,
			user_id TEXT,
			public_key BLOB,
			attestation_type TEXT,
			aaguid BLOB,
			sign_count INTEGER,
			created_at TIMESTAMP,
			last_used_at TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_credentials_user_id ON credentials(user_id);
	`)
	if err != nil {
		return nil, err
	}

	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) StoreCredential(userID string, cred *webauthn.Credential) error {
	_, err := s.db.Exec(`
		INSERT INTO credentials (
			id, user_id, public_key, attestation_type, aaguid, 
			sign_count, created_at, last_used_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		cred.ID, userID, cred.PublicKey, cred.AttestationType,
		cred.AAGUID, cred.SignCount, cred.CreatedAt, cred.LastUsedAt,
	)
	return err
}

func (s *SQLiteStore) GetCredential(credentialID []byte) (*webauthn.Credential, error) {
	var cred webauthn.Credential
	err := s.db.QueryRow(`
		SELECT id, public_key, attestation_type, aaguid, 
			   sign_count, created_at, last_used_at 
		FROM credentials WHERE id = ?`, credentialID).Scan(
		&cred.ID, &cred.PublicKey, &cred.AttestationType,
		&cred.AAGUID, &cred.SignCount, &cred.CreatedAt, &cred.LastUsedAt,
	)
	if err != nil {
		return nil, err
	}
	return &cred, nil
}

func (s *SQLiteStore) GetCredentialsByUser(userID string) ([]*webauthn.Credential, error) {
	rows, err := s.db.Query(`
		SELECT id, public_key, attestation_type, aaguid, 
			   sign_count, created_at, last_used_at 
		FROM credentials WHERE user_id = ?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []*webauthn.Credential
	for rows.Next() {
		var cred webauthn.Credential
		err := rows.Scan(
			&cred.ID, &cred.PublicKey, &cred.AttestationType,
			&cred.AAGUID, &cred.SignCount, &cred.CreatedAt, &cred.LastUsedAt,
		)
		if err != nil {
			return nil, err
		}
		creds = append(creds, &cred)
	}
	return creds, nil
}

func (s *SQLiteStore) UpdateCredential(cred *webauthn.Credential) error {
	_, err := s.db.Exec(`
		UPDATE credentials 
		SET sign_count = ?, last_used_at = ? 
		WHERE id = ?`,
		cred.SignCount, cred.LastUsedAt, cred.ID,
	)
	return err
}
