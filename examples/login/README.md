# login

A web app that demonstrate an OAuth2 client login.

### Prerequisites

1. [Tell Crossid about your app.](https://developer.crossid.io/docs/guides/get-started/add-app)
1. Setup HTTPS reverse proxy (see below)

### Setup HTTPS

To avoid security issues, this sample expects to be serves by HTTPS.

Let's use [Caddy](https://caddyserver.com/) to route traffic from port 443 to 3005.

```bash
caddy reverse-proxy --from localhost:443 --to localhost:3005
```

### Run the app

```bash
git clone https://github.com/crossid/crossid-go-samples && cd crossid-go-samples

# Replace with your crossid tenant and app details
go run login/*.go -issuer-url https://<tenant>.crossid.io/oauth2 --client-id=<client_id> --client-secret=<client_secret> --audience=myapp
```

Browser should be opened automatically, a successful login displays Access Token and ID Token.

New to Crossid? check out the [get started](https://developer.crossid.io/docs/guides/get-started]) guide
