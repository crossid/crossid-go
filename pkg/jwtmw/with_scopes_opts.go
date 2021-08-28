package jwtmw

import (
	"context"
	"github.com/golang-jwt/jwt/v4"
	"net/http"
)

type ConjunctionKind int

const (
	AND ConjunctionKind = iota
	OR
)

type withScopesOpts struct {
	// TokenCtxKey is the context key of an authenticated token value, typically set by the JWT middleware.
	TokenCtxKey interface{}
	// TokenFromContext extracts an authenticated token from context.
	// It assumes some prior middleware authenticated the token and put it in context, typically by the JWT middleware.
	// default implementation is naive as r.Context().Value(TokenCtxKey).(*jwt.Token)
	TokenFromContext func(ctx context.Context) (*jwt.Token, error)
	ClaimsFromToken  claimFromTokenFunc
	// Conjunction defines whether all scopes (AND) are required or one (OR)
	// of the provided scopes is sufficient for the request to be accepted.
	Conjunction ConjunctionKind
	// ErrorWriter writes an error into w
	ErrorWriter errorWriter
	// Logger logs various messages
	Logger        logger
	scopesChecker func(required []string, candidates []string) error
}

type WithScopesOpt func(*withScopesOpts)

func WithConjunction(c ConjunctionKind) WithScopesOpt {
	return func(o *withScopesOpts) {
		o.Conjunction = c
	}
}

func WithErrorWriter(w errorWriter) WithScopesOpt {
	return func(o *withScopesOpts) {
		o.ErrorWriter = w
	}
}

func WithTokenCtxKey(k interface{}) WithScopesOpt {
	return func(o *withScopesOpts) {
		o.TokenCtxKey = k
	}
}

func WithClaimsFromToken(f claimFromTokenFunc) WithScopesOpt {
	return func(o *withScopesOpts) {
		o.ClaimsFromToken = f
	}
}

func newWithScopesOpts(opts []WithScopesOpt) *withScopesOpts {
	o := new(withScopesOpts)
	for _, oo := range opts {
		oo(o)
	}

	// defaults
	if o.ErrorWriter == nil {
		o.ErrorWriter = func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, err.Error(), http.StatusForbidden)
		}
	}

	if o.Logger == nil {
		o.Logger = func(level Level, format string, args ...interface{}) {}
	}

	if o.TokenFromContext == nil {
		o.TokenFromContext = func(ctx context.Context) (*jwt.Token, error) {
			tv := ctx.Value(o.TokenCtxKey)
			if tv == nil {
				return nil, ErrMissingToken
			}

			return tv.(*jwt.Token), nil
		}
	}

	if o.TokenCtxKey == nil {
		o.TokenCtxKey = TokenCtxKey
	}

	if o.Conjunction == OR {
		o.scopesChecker = scopesCheckerOR
	} else {
		o.scopesChecker = scopesCheckerAND
	}

	if o.ClaimsFromToken == nil {
		o.ClaimsFromToken = DefaultClaimsFromToken
	}

	return o
}
