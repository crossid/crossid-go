package jwtmw

import (
	"context"
	"github.com/golang-jwt/jwt/v4"
	"net/http"
)

const (
	TokenCtxKey = "crossidTokenKey"
)

// tokenValidator validates that t and c are valid.
type tokenValidator func(r *http.Request, t *jwt.Token, c jwt.Claims) error

type Keyfunc = func(ctx context.Context, t *jwt.Token) (interface{}, error)

// JwtMiddlewareOpts describes the options of the JWTMiddleware
type JwtMiddlewareOpts struct {
	// TokenFromRequest extracts the bearer token from r
	TokenFromRequest tokenFromRequest
	// KeyFunc receives the parsed token and should return the key for validating.
	// this can be a secret or a key
	KeyFunc Keyfunc
	// SigningMethod defines the algorithm that should be used when verifying tokens.
	SigningMethod jwt.SigningMethod
	// Validate validates that the parsed token and claims are valid
	Validate tokenValidator
	// Claims will contain the JWT claims, decoded into the provided struct by reference.
	// It is advised to use jwt.MapClaims for dynamic map or jwt.StandardClaims for standard claims with type safety.
	// Where those implementations already implements the Valid() method to verify standard claims such as exp, iat, nbf.
	// and also provides convenience tools to perform extra validations such `VerifyAudience
	Claims jwt.Claims
	// Optional is true if no error should be returned in case token was not specified
	// If true and no token given, the middleware will continue the chain but no token will be put in request context.
	// If false and no token was given, the this middleware will render an error and stop the chain.
	Optional bool
	// ErrorWriter writes an error into w
	ErrorWriter errorWriter
	// Logger logs various messages
	Logger logger
	// TokenCtxKey is the context key of a valid token that is put in the request's context.
	TokenCtxKey interface{}
	// WithContext is a way to put another context in request chain.
	// this let consumer enhances context with a key such as user loaded from db, etc.
	WithContext func(ctx context.Context) (context.Context, error)
}

func mergeOpts(opts ...*JwtMiddlewareOpts) *JwtMiddlewareOpts {
	opt := JwtMiddlewareOpts{
		TokenFromRequest: BearerTokenFromRequest,
		Optional:         false,
		ErrorWriter: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, err.Error(), http.StatusUnauthorized)
		},
		Logger:      func(level Level, format string, args ...interface{}) {},
		TokenCtxKey: TokenCtxKey,
		WithContext: func(c context.Context) (context.Context, error) { return c, nil },
	}

	for _, o := range opts {
		if o == nil {
			continue
		}
		if o.TokenFromRequest != nil {
			opt.TokenFromRequest = o.TokenFromRequest
		}
		if o.SigningMethod != nil {
			opt.SigningMethod = o.SigningMethod
		}
		if o.KeyFunc != nil {
			opt.KeyFunc = o.KeyFunc
		}
		if o.Validate != nil {
			opt.Validate = o.Validate
		}
		if o.Claims != nil {
			opt.Claims = o.Claims
		}
		if o.Optional {
			opt.Optional = o.Optional
		}
		if o.ErrorWriter != nil {
			opt.ErrorWriter = o.ErrorWriter
		}
		if o.Logger != nil {
			opt.Logger = o.Logger
		}
		if o.TokenCtxKey != nil {
			opt.TokenCtxKey = o.TokenCtxKey
		}
		if o.WithContext != nil {
			opt.WithContext = o.WithContext
		}
	}

	return &opt
}
