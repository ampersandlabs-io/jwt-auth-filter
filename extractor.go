package JWTAuthFilter

import (
	"net/http"
	"strings"
)

func extractAuthToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", ErrNoTokenInRequest // No error, just no token
	}

	// TODO: Make this a bit more robust, parsing-wise
	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "jwt" {
		return "", ErrInvalidTokenFormat
	}

	return authHeaderParts[1], nil
}
