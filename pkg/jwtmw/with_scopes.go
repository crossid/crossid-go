package jwtmw

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"net/http"
)

type claimFromTokenFunc = func(ctx context.Context, t *jwt.Token) ([]string, error)

func DefaultClaimsFromToken(ctx context.Context, t *jwt.Token) ([]string, error) {
	switch v := t.Claims.(type) {
	case jwt.MapClaims:
		scpv := v[ScopesClaim]

		if arr, ok := scpv.([]string); ok {
			return arr, nil
		} else if arr, ok := scpv.([]interface{}); ok {
			strs := make([]string, len(arr))
			for i, s := range arr {
				strs[i] = s.(string)
			}
			return strs, nil
		}

		return []string{}, nil
	default:
		return nil, fmt.Errorf("claim type '%T' is unknown, implement custom ClaimsFromToken option", v)
	}
}

func WithScopes(required ...string) func(next http.Handler) http.Handler {
	return WithScopesCustom(required)
}

func WithScopesCustom(required []string, opt ...WithScopesOpt) func(next http.Handler) http.Handler {
	if required == nil || len(required) < 1 {
		panic("required must be set with at least one scope.")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			opts := newWithScopesOpts(opt)
			tok, err := opts.TokenFromContext(r.Context())
			if err != nil {
				opts.Logger(Info, "missing token")
				opts.ErrorWriter(w, r, err)
				return
			}

			cl, err := opts.ClaimsFromToken(r.Context(), tok)
			if err != nil {
				opts.Logger(Info, "error extracting claims: %s", err)
				opts.ErrorWriter(w, r, ErrExtractingClaims)
				return
			}

			if err := opts.ScopesChecker(r.Context(), required, cl); err != nil {
				opts.Logger(Info, "scopes errors: %s", err)
				opts.ErrorWriter(w, r, ErrMissingClaim)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
