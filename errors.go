package webauthn

import "errors"

var (
	// ErrMissingRPDisplayName is returned when RPDisplayName is not provided
	ErrMissingRPDisplayName = errors.New("relying party display name is required")

	// ErrMissingRPID is returned when RPID is not provided
	ErrMissingRPID = errors.New("relying party ID is required")

	// ErrMissingRPOrigins is returned when RPOrigins is empty
	ErrMissingRPOrigins = errors.New("at least one relying party origin is required")
)
