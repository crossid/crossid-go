/*
Package jwtmw provides an HTTP middleware that parses a JWT token and put it in context
*/
package jwtmw

import (
	"context"
	"errors"
	"github.com/golang-jwt/jwt/v4"
	"net/http"
)

// JWT returns a new middleware that performs JWT validations.
type JWT struct {
	opts JwtMiddlewareOpts
}

func NewJWT(opts ...*JwtMiddlewareOpts) *JWT {
	return &JWT{
		opts: *mergeOpts(opts...),
	}
}

func (j *JWT) Validate(r *http.Request) (*jwt.Token, error) {
	bearer, err := j.opts.TokenFromRequest(r)
	if err != nil {
		j.opts.Logger(Info, "error extracting token: %s", err)
		return nil, ErrExtractingToken
	}

	if bearer == "" {
		j.opts.Logger(Info, "missing token")
		return nil, ErrMissingToken
	}

	// validates and return a token
	var c = j.opts.Claims
	if c == nil {
		c = jwt.MapClaims{}
	}

	pt, err := jwt.ParseWithClaims(bearer, c, func(t *jwt.Token) (interface{}, error) {
		return j.opts.KeyFunc(r.Context(), t)
	})
	if err != nil {
		j.opts.Logger(Info, "error parsing token: %v", err)
		return nil, ErrInvalidToken
	}

	if j.opts.SigningMethod != nil && j.opts.SigningMethod.Alg() != pt.Header["alg"] {
		j.opts.Logger(Info, "invalid signing algorithm, expected '%s' but got '%s'", j.opts.SigningMethod.Alg(), pt.Header["alg"])
		return nil, ErrInvalidToken
	}

	if !pt.Valid {
		j.opts.Logger(Info, "invalid token (typically due to claims invalidation)")
		return nil, ErrInvalidToken
	}

	if j.opts.Validate != nil {
		if err := j.opts.Validate(r, pt, c); err != nil {
			j.opts.Logger(Info, "custom validation failed: %s", err)
			return nil, ErrInvalidToken
		}
	}

	return pt, nil
}

func (j *JWT) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, err := j.Validate(r)
		if err != nil {
			if j.opts.Optional && errors.Is(err, ErrMissingToken) {
				j.opts.Logger(Debug, "token is missing")
				h.ServeHTTP(w, r)
				return
			}

			j.opts.ErrorWriter(w, r, err)
			return
		}

		ctx, err := j.opts.WithContext(context.WithValue(r.Context(), j.opts.TokenCtxKey, tok))
		if err != nil {
			j.opts.Logger(Debug, "WithContext returned error: %s", err)
			j.opts.ErrorWriter(w, r, err)
			return
		}
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}
