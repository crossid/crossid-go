package jwtmw

import (
	"fmt"
	"net/http"
	"strings"
)

// tokenFromRequest extracts a bearer token from r and returns it
// an error indicates that there was an error while extracting the
// token (e.g., invalid token, token was prefixed with wrong type, etc...)
// which will eventually cause the middleware to block the request.
// an absence of a token should return an empty token (`"", nil`) rather an error.
type tokenFromRequest func(r *http.Request) (string, error)

const (
	// BearerPrefix must be set as a prefix before the actual token
	BearerPrefix    = "Bearer"
	// BearerHeaderKey is the http header name of the token
	BearerHeaderKey = "Authorization"
)

// BearerTokenFromRequest extracts a bearer token from r
// This is a naive implementation that tries to extract a token from request header.
// More advanced extractors may try to extract tokens from forms, cookies, etc.
func BearerTokenFromRequest(r *http.Request) (string, error) {
	if r.Header.Get(BearerHeaderKey) == "" {
		return "", nil
	}

	p := strings.Split(r.Header.Get(BearerHeaderKey), " ")

	if len(p) == 2 && strings.EqualFold(p[0], BearerPrefix) {
		return p[1], nil
	}

	return "", fmt.Errorf("missing or invalid token")
}
