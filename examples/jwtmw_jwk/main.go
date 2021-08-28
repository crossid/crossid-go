package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/MicahParks/keyfunc"
	"github.com/crossid/crossid-go/pkg/jwtmw"
	"github.com/golang-jwt/jwt/v4"
	"log"
	"net/http"
)

// main is an example of an http server that protect a route by a OAuth2 JWT.
// before endpoint is invoked, a middleware ensures the token is valid and that the user is assigned to the relevant scopes.
//
//
// run example by: go run jwtmw_jwk/main.go --jwks-endpoint https://<tenant>.crossid.io/oauth2/.well-known/jwks.json
// to get a token, see examples/login folder
// once you have a token run:
// curl -i  http://0.0.0.0:3000 -H "Authorization: Bearer <TOKEN>"
func main() {
	jwksURLPtr := flag.String("jwks-endpoint", "https://demo.crossid.io/oauth2/.well-known/jwks.json", "Well known JWKs endpoint")
	flag.Parse()

	opts := keyfunc.Options{
		RefreshErrorHandler: func(err error) {
			log.Printf("There was an error with the jwt.KeyFunc\nError:%s\n", err.Error())
		},
	}

	// Create the JWKs from the resource at the given URL.
	jwks, err := keyfunc.Get(*jwksURLPtr, opts)
	if err != nil {
		log.Fatalf("Failed to create JWKs from resource at the given URL.\nError:%s\n", err.Error())
	}

	// Create the middleware provider.
	authmw := jwtmw.NewJWT(&jwtmw.JwtMiddlewareOpts{
		// Ensure signing method to avoid tokens ׳with "none" method.
		SigningMethod: jwt.SigningMethodRS256,
		Logger: func(level jwtmw.Level, format string, args ...interface{}) {
			log.Fatalf(format, args...)
		},
		KeyFunc: func(ctx context.Context, t *jwt.Token) (interface{}, error) {
			return jwks.KeyFunc(t)
		},
	})

	// Create a middleware that ensures token has the "openid" and "profile" scope.
	withScopes := jwtmw.WithScopes("openid", "profile")

	// Our protected handler
	var protectedHandler = http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		// tok is the verified JWT token
		tok := req.Context().Value(jwtmw.TokenCtxKey)

		// Write the JWT claims.
		for claim, value := range tok.(*jwt.Token).Claims.(jwt.MapClaims) {
			_, _ = writer.Write([]byte(fmt.Sprintf("  %s :%#v\n", claim, value)))
		}

		// Write a 200 response.
		writer.WriteHeader(200)
	})

	// wrap handler with auth middlewares
	app := authmw.Handler(withScopes(protectedHandler))

	fmt.Println("serving on 0.0.0.0:3000")
	if err = http.ListenAndServe("0.0.0.0:3000", app); err != nil {
		panic(err.Error())
	}
}
