package JWTAuthFilter

import (
	"errors"
	"io"
	"net/http"
)

type key string

// RequestUserIDKey represents key used to refer to user_id stored in request
const RequestUserIDKey key = "user_id"

// ErrNoTokenInRequest is an error indicating the request was made without an auth token in the header
// ErrInvalidTokenFormat is an error indicating the token was malformed
var (
	ErrNoTokenInRequest   = errors.New("No authentication token present")
	ErrInvalidTokenFormat = errors.New("Authorization header format must be JWT {token}")
)

// JWTAuthFilter is designed to be a middleware which verifies each server request
func JWTAuthFilter(inner http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if r, err := validateRequest(r); err != nil {
			w.Header().Add("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"detail": "`+err.Error()+`"}`)
		} else {
			inner.ServeHTTP(w, r)
		}

	})

}
