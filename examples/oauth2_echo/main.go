package main

import (
	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt"
	jwtv4 "github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"log"
	"net/http"
)

// how to use Echo go web framework with Crossid
// for more info see: https://developer.crossid.io/blog/crossid-with-echo
func main() {
	// Create the JWKs from the resource at the given URL.
	jwks, err := keyfunc.Get("https://asaf.preview.crossid.io/oauth2/.well-known/jwks.json", keyfunc.Options{
		RefreshErrorHandler: func(err error) {
			log.Printf("There was an error with the jwt.KeyFunc\nError:%s\n", err.Error())
		},
	})

	if err != nil {
		log.Fatalf("Failed to create JWKs from resource at the given URL.\nError:%s\n", err.Error())
	}

	authmw := middleware.JWTWithConfig(middleware.JWTConfig{
		Skipper: func(context echo.Context) bool {
			return context.Path() == "/"
		},
		KeyFunc: func(token *jwt.Token) (interface{}, error) {
			t, _, err := new(jwtv4.Parser).ParseUnverified(token.Raw, jwtv4.MapClaims{})
			if err != nil {
				return nil, err
			}
			return jwks.KeyFunc(t)
		},
	})

	e := echo.New()
	e.Use(authmw)
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Public!")
	})
	e.GET("/admin", func(c echo.Context) error {
		tok := c.Get("user").(*jwt.Token)
		cl := tok.Claims.(jwt.MapClaims)["scp"].([]interface{})
		allowed := false
		for _, c := range cl {
			if c == "admin" {
				allowed = true
				break
			}
		}

		if !allowed {
			return c.JSON(http.StatusForbidden, map[string]string{"message": "Insufficient privileges"})
		}

		return c.String(http.StatusOK, "Admin!")
	})

	e.GET("/whoami", func(c echo.Context) error {
		cl := c.Get("user").(*jwt.Token).Claims.(jwt.MapClaims)
		return c.JSONPretty(http.StatusOK, cl, "  ")
	})

	e.Logger.Fatal(e.Start(":1323"))
}
