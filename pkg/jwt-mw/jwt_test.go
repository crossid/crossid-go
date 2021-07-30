package jwt_mw

import (
	"encoding/json"
	"fmt"
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

var validKeyFunc = func(token *jwt.Token) (interface{}, error) {
	return secret, nil
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
		name        string
		opts        *JwtMiddlewareOpts
		jwt         string
		shouldBlock bool
		resp        func(resp *http.Response)
	}{
		{
			name:        "should continue with a valid jwt and put parsed token in ctx",
			shouldBlock: false,
			jwt:         signJWT(t, jwt.MapClaims{"foo": "bar"}),
			opts: &JwtMiddlewareOpts{
				KeyFunc: validKeyFunc,
			},
			resp: func(resp *http.Response) {
				b, err := ioutil.ReadAll(resp.Body)
				assertNoError(t, err)
				assertTrue(t, gjson.Get(string(b), "Valid").Bool(), "invalid jwt")
				if gjson.Get(string(b), "Claims").String() != `{"foo":"bar"}` {
					t.Fatalf("claims mismatch")
				}
			},
		},
		{
			name:        "should decode into custom claims struct",
			shouldBlock: false,
			jwt:         signJWT(t, jwt.MapClaims{"thefoo": "bar"}),
			opts: &JwtMiddlewareOpts{
				KeyFunc: validKeyFunc,
				Claims:  &fooClaim{},
			},
			resp: func(resp *http.Response) {
				b, err := ioutil.ReadAll(resp.Body)
				assertNoError(t, err)
				assertTrue(t, gjson.Get(string(b), "Valid").Bool(), "invalid jwt")
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
				assertNoError(t, err)
			}},
			resp: func(resp *http.Response) {
				b, err := ioutil.ReadAll(resp.Body)
				assertNoError(t, err)
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
			jwt:         signJWT(t, nil),
			opts: &JwtMiddlewareOpts{
				KeyFunc: validKeyFunc,
				Claims:  &fooClaim{},
			},
		},
		{
			name:        "should fail if exp < now",
			shouldBlock: true,
			jwt: signJWT(t, jwt.StandardClaims{
				ExpiresAt: time.Now().Add(-1 * time.Second).Unix(),
			}),
			opts: &JwtMiddlewareOpts{
				KeyFunc: validKeyFunc,
			},
		},
		{
			name:        "should fail if iat > now",
			shouldBlock: true,
			jwt: signJWT(t, jwt.StandardClaims{
				IssuedAt: time.Now().Add(2 * time.Second).Unix(),
			}),
			opts: &JwtMiddlewareOpts{
				KeyFunc: validKeyFunc,
			},
		},
		{
			name:        "should fail if nbf > now",
			shouldBlock: true,
			jwt: signJWT(t, jwt.StandardClaims{
				NotBefore: time.Now().Add(2 * time.Second).Unix(),
			}),
			opts: &JwtMiddlewareOpts{
				KeyFunc: validKeyFunc,
			},
		},
		{
			name:        "should not fail if exp < now with custom claim struct",
			shouldBlock: false,
			jwt: signJWT(t, jwt.StandardClaims{
				ExpiresAt: time.Now().Add(-1 * time.Second).Unix(),
			}),
			opts: &JwtMiddlewareOpts{
				KeyFunc: validKeyFunc,
				Claims:  &okClaim{},
			},
		},
		{
			name:        "assert audience and issuer",
			shouldBlock: false,
			jwt: signJWT(t, jwt.StandardClaims{
				Issuer:   "crossid.io",
				Audience: "acme.io",
			}),
			opts: &JwtMiddlewareOpts{
				KeyFunc: validKeyFunc,
				Validate: func(to *jwt.Token, c jwt.Claims) error {
					cl := c.(jwt.MapClaims)
					assertTrue(t, cl.VerifyIssuer("crossid.io", true), "invalid issuer")
					assertTrue(t, !cl.VerifyAudience("foo", true), "invalid issuer")
					assertTrue(t, cl.VerifyAudience("acme.io", true), "invalid audience")
					assertTrue(t, !cl.VerifyAudience("foo", true), "invalid audience")
					return nil
				},
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			visited := false
			hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

func signJWT(t *testing.T, claims jwt.Claims) string {
	tok := jwt.New(jwt.SigningMethodHS256)
	tok.Claims = claims
	b, err := tok.SignedString(secret)
	if err != nil {
		t.Fatalf(err.Error())
	}
	return fmt.Sprintf("%s %s", BearerPrefix, b)
}

func assertNoError(t *testing.T, err error) {
	if err != nil {
		t.Fatalf("expected no error but got %s", err)
	}
}

func assertTrue(t *testing.T, v bool, msg string) {
	if !v {
		t.Fatalf(msg)
	}
}
