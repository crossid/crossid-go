package jwtmw

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"github.com/crossid/crossid-go/pkg/x/testx"
	"github.com/golang-jwt/jwt"
	"github.com/tidwall/gjson"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var secret = []byte("secret")

var prkey, _ = rsa.GenerateKey(rand.Reader, 2048)

type fooKey struct{}

var validKeyFuncHS256 = func(ctx context.Context, token *jwt.Token) (interface{}, error) {
	return secret, nil
}

func newValidKeyFuncRS256(key *rsa.PublicKey) Keyfunc {
	return func(ctx context.Context, token *jwt.Token) (interface{}, error) {
		return key, nil
	}
}

type fooClaim struct {
	Foo string `json:"thefoo"`
}

func (f *fooClaim) Valid() error {
	if f.Foo != "bar" {
		return fmt.Errorf("invalid claims")
	}

	return nil
}

type okClaim struct {
	Exp int64 `json:"exp"`
}

func (f *okClaim) Valid() error {
	return nil
}

func TestJWT_Handler(t *testing.T) {
	for k, tc := range []struct {
		name           string
		opts           *JwtMiddlewareOpts
		jwt            string
		shouldBlock    bool
		resp           func(resp *http.Response)
		inspectRequest func(r *http.Request) error
	}{
		{
			name:        "should continue with a valid jwt and put parsed token in ctx",
			shouldBlock: false,
			jwt:         signHS256JWT(t, jwt.MapClaims{"foo": "bar"}),
			opts: &JwtMiddlewareOpts{
				KeyFunc: validKeyFuncHS256,
			},
			resp: func(resp *http.Response) {
				b, err := ioutil.ReadAll(resp.Body)
				testx.AssertNoError(t, err)
				testx.AssertTrue(t, gjson.Get(string(b), "Valid").Bool(), "invalid jwt")
				if gjson.Get(string(b), "Claims").String() != `{"foo":"bar"}` {
					t.Fatalf("claims mismatch")
				}
			},
		},
		{
			name:        "should decode into custom claims struct",
			shouldBlock: false,
			jwt:         signHS256JWT(t, jwt.MapClaims{"thefoo": "bar"}),
			opts: &JwtMiddlewareOpts{
				KeyFunc: validKeyFuncHS256,
				Claims:  &fooClaim{},
			},
			resp: func(resp *http.Response) {
				b, err := ioutil.ReadAll(resp.Body)
				testx.AssertNoError(t, err)
				testx.AssertTrue(t, gjson.Get(string(b), "Valid").Bool(), "invalid jwt")
				if gjson.Get(string(b), "Claims").String() != `{"thefoo":"bar"}` {
					t.Fatalf("claims mismatch")
				}
			},
		},
		{
			name:        "custom error writer",
			shouldBlock: true,
			opts: &JwtMiddlewareOpts{ErrorWriter: func(w http.ResponseWriter, r *http.Request, err error) {
				if err != ErrMissingToken {
					t.Fatalf("expected ErrMissingToken but got %s", err)
				}

				w.WriteHeader(http.StatusUnauthorized)
				_, err = w.Write([]byte(fmt.Sprintf(`{"error": "%s"}`, err.Error())))
				testx.AssertNoError(t, err)
			}},
			resp: func(resp *http.Response) {
				b, err := ioutil.ReadAll(resp.Body)
				testx.AssertNoError(t, err)
				if v := gjson.GetBytes(b, "error").String(); v != ErrMissingToken.Error() {
					t.Fatalf("expected ErrMissingToken but got %s", v)
				}
			},
		},
		{
			name:        "should block when no token and optional=false",
			shouldBlock: true,
		},
		{
			name:        "should continue when no token and optional=true",
			opts:        &JwtMiddlewareOpts{Optional: true},
			shouldBlock: false,
		},
		{
			name: "should fail if tokenFromRequest fails",
			opts: &JwtMiddlewareOpts{
				TokenFromRequest: func(r *http.Request) (string, error) {
					return "", fmt.Errorf("bad")
				},
			},
			shouldBlock: true,
			resp: func(resp *http.Response) {
				b, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf(err.Error())
				}
				if strings.Trim(string(b), "\n") != ErrExtractingToken.Error() {
					t.Fatalf("invalid err")
				}
			},
		},
		{
			name:        "should fail if claims.Valid() is false",
			shouldBlock: true,
			jwt:         signHS256JWT(t, nil),
			opts: &JwtMiddlewareOpts{
				KeyFunc: validKeyFuncHS256,
				Claims:  &fooClaim{},
			},
		},
		{
			name:        "should fail if exp < now",
			shouldBlock: true,
			jwt: signHS256JWT(t, jwt.StandardClaims{
				ExpiresAt: time.Now().Add(-1 * time.Second).Unix(),
			}),
			opts: &JwtMiddlewareOpts{
				KeyFunc: validKeyFuncHS256,
			},
		},
		{
			name:        "should fail if iat > now",
			shouldBlock: true,
			jwt: signHS256JWT(t, jwt.StandardClaims{
				IssuedAt: time.Now().Add(2 * time.Second).Unix(),
			}),
			opts: &JwtMiddlewareOpts{
				KeyFunc: validKeyFuncHS256,
			},
		},
		{
			name:        "should fail if nbf > now",
			shouldBlock: true,
			jwt: signHS256JWT(t, jwt.StandardClaims{
				NotBefore: time.Now().Add(2 * time.Second).Unix(),
			}),
			opts: &JwtMiddlewareOpts{
				KeyFunc: validKeyFuncHS256,
			},
		},
		{
			name:        "should not fail if exp < now with custom claim struct",
			shouldBlock: false,
			jwt: signHS256JWT(t, jwt.StandardClaims{
				ExpiresAt: time.Now().Add(-1 * time.Second).Unix(),
			}),
			opts: &JwtMiddlewareOpts{
				KeyFunc: validKeyFuncHS256,
				Claims:  &okClaim{},
			},
		},
		{
			name:        "assert audience and issuer",
			shouldBlock: false,
			jwt: signHS256JWT(t, jwt.StandardClaims{
				Issuer:   "crossid.io",
				Audience: "acme.io",
			}),
			opts: &JwtMiddlewareOpts{
				KeyFunc: validKeyFuncHS256,
				Validate: func(_ *http.Request, to *jwt.Token, c jwt.Claims) error {
					cl := c.(jwt.MapClaims)
					testx.AssertTrue(t, cl.VerifyIssuer("crossid.io", true), "invalid issuer")
					testx.AssertTrue(t, !cl.VerifyAudience("foo", true), "invalid issuer")
					testx.AssertTrue(t, cl.VerifyAudience("acme.io", true), "invalid audience")
					testx.AssertTrue(t, !cl.VerifyAudience("foo", true), "invalid audience")
					testx.AssertTrue(t, to.Valid, "token should be valid")
					return nil
				},
			},
		},
		{
			name: "should sign with RS256",
			jwt: signRS256JWT(t, prkey, jwt.StandardClaims{
				Issuer:   "crossid.io",
				Audience: "acme.io",
			}),
			opts: &JwtMiddlewareOpts{
				KeyFunc:       newValidKeyFuncRS256(&prkey.PublicKey),
				SigningMethod: jwt.SigningMethodRS256,
			},
		},
		{
			name:        "should fail when JWT signed with different algo (HS256) than expected (RS256)",
			shouldBlock: true,
			jwt: signHS256JWT(t, jwt.StandardClaims{
				Issuer:   "crossid.io",
				Audience: "acme.io",
			}),
			opts: &JwtMiddlewareOpts{
				KeyFunc:       validKeyFuncHS256,
				SigningMethod: jwt.SigningMethodRS256,
			},
		},
		{
			name: "withContext",
			jwt: signHS256JWT(t, jwt.StandardClaims{
				Issuer:   "crossid.io",
				Audience: "acme.io",
			}),
			opts: &JwtMiddlewareOpts{
				KeyFunc: validKeyFuncHS256,
				WithContext: func(ctx context.Context) (context.Context, error) {
					return context.WithValue(ctx, fooKey{}, "bar"), nil
				},
			},
			inspectRequest: func(r *http.Request) error {
				if r.Context().Value(fooKey{}) != "bar" {
					return fmt.Errorf("context value key 'foo' is not 'bar'")
				}
				return nil
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			visited := false
			hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.inspectRequest != nil {
					testx.AssertNoError(t, tc.inspectRequest(r))
				}
				visited = true
				tok := r.Context().Value(TokenCtxKey)
				if err := json.NewEncoder(w).Encode(tok); err != nil {
					t.Fatalf(err.Error())
				}
			})

			r, err := http.NewRequest(http.MethodGet, "/", nil)
			if err != nil {
				t.Fatalf(err.Error())
			}
			if tc.jwt != "" {
				r.Header.Set(BearerHeaderKey, tc.jwt)
			}
			w := httptest.NewRecorder()
			NewJWT(tc.opts).Handler(hf).ServeHTTP(w, r)

			if tc.shouldBlock && w.Code != http.StatusUnauthorized {
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

func signHS256JWT(t *testing.T, claims jwt.Claims) string {
	tok := jwt.New(jwt.SigningMethodHS256)
	tok.Claims = claims
	b, err := tok.SignedString(secret)
	if err != nil {
		t.Fatalf(err.Error())
	}
	return fmt.Sprintf("%s %s", BearerPrefix, b)
}

func signRS256JWT(t *testing.T, key *rsa.PrivateKey, c jwt.Claims) string {
	jt := jwt.New(jwt.GetSigningMethod(jwt.SigningMethodRS256.Name))
	jt.Claims = c
	b, err := jt.SignedString(key)
	testx.AssertNoError(t, err)
	return fmt.Sprintf("%s %s", BearerPrefix, b)
}
