package jwtmw

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"net/http"
	"net/http/httptest"
	"testing"
)

type claimsWithScopes struct {
	jwt.StandardClaims
	Scopes []string `json:"scp"`
}

func claimsFromTok(ctx context.Context, t *jwt.Token) ([]string, error) {
	return t.Claims.(*claimsWithScopes).Scopes, nil
}

type conjunctionKind int

const (
	AND conjunctionKind = iota
	OR
)

func TestWithScopesCustom(t *testing.T) {
	for k, tc := range []struct {
		name           string
		jwtopts        *JwtMiddlewareOpts
		c              conjunctionKind
		r              []string
		jwt            string
		shouldBlock    bool
		resp           func(resp *http.Response)
		inspectRequest func(r *http.Request) error
	}{
		{
			name: "case ok when all scope match (defaults to AND conjunction)",
			jwt: signHS256JWT(t, claimsWithScopes{
				StandardClaims: jwt.StandardClaims{
					Issuer:   "crossid.io",
					Audience: "acme.io",
				},
				Scopes: []string{"foo", "bar", "baz"},
			}),
			r: []string{"foo", "bar"},
			jwtopts: &JwtMiddlewareOpts{
				KeyFunc: validKeyFuncHS256,
				Claims:  &claimsWithScopes{},
			},
		},
		{
			name: "case ok when one of the scope match (defaults to OR conjunction)",
			c:    OR,
			jwt: signHS256JWT(t, claimsWithScopes{
				StandardClaims: jwt.StandardClaims{
					Issuer:   "crossid.io",
					Audience: "acme.io",
				},
				Scopes: []string{"foo", "baz"},
			}),
			r: []string{"foo", "bar"},
			jwtopts: &JwtMiddlewareOpts{
				KeyFunc: validKeyFuncHS256,
				Claims:  &claimsWithScopes{},
			},
		},
		{
			name: "should block when not all scopes match (AND conjunction)",
			jwt: signHS256JWT(t, claimsWithScopes{
				StandardClaims: jwt.StandardClaims{
					Issuer:   "crossid.io",
					Audience: "acme.io",
				},
				Scopes: []string{"foo", "baz"},
			}),
			c:           AND,
			shouldBlock: true,
			r:           []string{"foo", "bar"},
			jwtopts: &JwtMiddlewareOpts{
				KeyFunc: validKeyFuncHS256,
				Claims:  &claimsWithScopes{},
			},
		},
		{
			name: "should block when not all scopes match (OR conjunction)",
			c:    OR,
			jwt: signHS256JWT(t, claimsWithScopes{
				StandardClaims: jwt.StandardClaims{
					Issuer:   "crossid.io",
					Audience: "acme.io",
				},
				Scopes: []string{"foo", "baz"},
			}),
			shouldBlock: true,
			r:           []string{"bar"},
			jwtopts: &JwtMiddlewareOpts{
				KeyFunc: validKeyFuncHS256,
				Claims:  &claimsWithScopes{},
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			r, err := http.NewRequest(http.MethodGet, "/", nil)
			if err != nil {
				t.Fatalf(err.Error())
			}

			if tc.jwt != "" {
				r.Header.Set(BearerHeaderKey, tc.jwt)
			}

			jmw := NewJWT(tc.jwtopts)
			var scf ScopesCheckerFunc
			if tc.c == AND {
				scf = scopesCheckerAND
			} else {
				scf = ScopesCheckerOR
			}

			smw := WithScopesCustom(tc.r, WithClaimsFromToken(claimsFromTok), WithScopesChecker(scf))
			visited := false
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				visited = true
			})
			w := httptest.NewRecorder()
			jmw.Handler(smw(h)).ServeHTTP(w, r)
			if tc.shouldBlock && w.Code != http.StatusForbidden {
				t.Fatalf("expected code 402 but got %d", w.Code)
			} else if !tc.shouldBlock && w.Code != http.StatusOK {
				t.Fatalf("expected code 200 but got %d", w.Code)
			}

			if tc.shouldBlock && visited {
				t.Fatalf("expected block but handler visited")
			}

			if tc.resp != nil {
				tc.resp(w.Result())
			}
		})
	}
}
