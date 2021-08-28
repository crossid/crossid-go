package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/julienschmidt/httprouter"
	"github.com/toqueteos/webbrowser"
	"golang.org/x/oauth2"
	"html/template"
	"net/http"
	"strings"
	"time"
)

var indexPage = template.Must(template.New("").Parse(`<html>
<body>
<h1>Crossid Samples</h1>
<ul>
<li><a href="{{ .URL }}">Login using code flow</a></li>
</body>
</html>
`))

var errorPage = template.Must(template.New("").Parse(`<html>
<body>
<h1>An error occurred</h1>
<h2>{{ .Name }}</h2>
<p>{{ .Description }}</p>
</body>
</html>
`))

var tokenUserResult = template.Must(template.New("").Parse(`<html>
<html>
<head></head>
<body>
<h1>Success!</h1>
<ul>
    <li>Access Token: <code>{{ .AccessToken }}</code></li>
	<li>Expires at: <code>{{ .Expiry }}</code></li>
    <li>Refresh Token: <code>{{ .RefreshToken }}</code></li>
    <li>ID Token: <code>{{ .IDToken }}</code></li>
</ul>
</body>
</html>`))

func main() {
	portPtr := flag.Int("port", 3005, "port")
	issuerBaseURLPtr := flag.String("issuer-url", "https://demo.crossid.io/oauth2", "Issuer URL")
	scopesPtr := flag.String("scope", "openid offline profile", "Requested scopes")
	redirectURLPtr := flag.String("redirect-url", "https://localhost/callback", "where to redirect after login")
	clientIDPtr := flag.String("client-id", "sample", "the registered client id in the authorization server")
	clientSecretPtr := flag.String("client-secret", "super-secret", "the registered client secret in the authorization server")
	audiencePtr := flag.String("audience", "https://api.example.com/products", "requested audience")
	promptPtr := flag.String("prompt", "consent", "consent or none")
	flag.Parse()

	externalLocation := "localhost"
	listenOn := fmt.Sprintf("%s:%d", externalLocation, *portPtr)
	conf := oauth2.Config{
		ClientID:     *clientIDPtr,
		ClientSecret: *clientSecretPtr,
		Endpoint: oauth2.Endpoint{
			TokenURL: *issuerBaseURLPtr + "/token",
			AuthURL:  *issuerBaseURLPtr + "/auth",
		},
		RedirectURL: *redirectURLPtr,
		Scopes:      strings.Split(*scopesPtr, " "),
	}

	state := RandomString(30)
	nonce := RandomString(30)

	authCodeURL := conf.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("audience", *audiencePtr),
		oauth2.SetAuthURLParam("nonce", nonce),
		//oauth2.SetAuthURLParam("max_age", *maxAge),
		oauth2.SetAuthURLParam("prompt", *promptPtr),
	)

	_ = webbrowser.Open("https://" + externalLocation)

	r := httprouter.New()
	server := &http.Server{Addr: listenOn, Handler: r}
	var shutdown = func() {
		time.Sleep(time.Second * 1)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()
		_ = server.Shutdown(ctx)
	}

	fmt.Println("listening on " + listenOn)
	fmt.Println("callback url https://" + externalLocation + "/callback")
	fmt.Printf("if browser is not opened automatically, navigate to: %s\n", "https://"+externalLocation)

	r.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		_ = indexPage.Execute(w, &struct{ URL string }{URL: authCodeURL})
	})

	type derr struct {
		Name        string
		Description string
		Hint        string
		Debug       string
	}

	r.GET("/callback", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		if len(r.URL.Query().Get("error")) > 0 {
			fmt.Printf("Got error: %s\n", r.URL.Query().Get("error_description"))

			w.WriteHeader(http.StatusInternalServerError)
			_ = errorPage.Execute(w, &derr{
				Name:        r.URL.Query().Get("error"),
				Description: r.URL.Query().Get("error_description"),
				Hint:        r.URL.Query().Get("error_hint"),
				Debug:       r.URL.Query().Get("error_debug"),
			})

			go shutdown()
			return
		}

		if r.URL.Query().Get("state") != state {
			fmt.Printf("states mismatch. Expected %s, got %s\n", state, r.URL.Query().Get("state"))

			w.WriteHeader(http.StatusInternalServerError)
			_ = errorPage.Execute(w, &derr{
				Name:        "states mismatch",
				Description: "Expected state " + state + ", got " + r.URL.Query().Get("state"),
			})
			go shutdown()
			return
		}

		code := r.URL.Query().Get("code")
		token, err := conf.Exchange(context.Background(), code)
		if err != nil {
			fmt.Printf("Unable to exchange code for token: %s\n", err)

			w.WriteHeader(http.StatusInternalServerError)
			_ = errorPage.Execute(w, &derr{
				Name: err.Error(),
			})
			go shutdown()
			return
		}

		idt := token.Extra("id_token")
		_ = tokenUserResult.Execute(w, struct {
			AccessToken  string
			RefreshToken string
			IDToken      string
			Expiry       string
		}{
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
			Expiry:       token.Expiry.Format(time.RFC1123),
			IDToken:      fmt.Sprintf("%v", idt),
		})

		go shutdown()
	})

	if err := server.ListenAndServe(); err != nil {
		fmt.Println(err)
	}
}
