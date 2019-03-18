package hashpass

import "errors"

var (
	// ErrInvalidHashType is the error returned when the hash type
	// is not valid.
	ErrInvalidHashType = errors.New("invalid hash type")

	// ErrInvalidSalt is the error returned when the salt
	// is not valid.
	ErrInvalidSalt = errors.New("invalid salt")

	// ErrInvalidSalt is the error returned when the hash length
	// is not valid.
	ErrInvalidLength = errors.New("invalid hash length")
)
