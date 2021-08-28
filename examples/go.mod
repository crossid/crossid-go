module github.com/crossid/crossid-go/examples

go 1.16

require (
	github.com/MicahParks/keyfunc v0.7.0
	github.com/crossid/crossid-go v0.0.0
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/golang-jwt/jwt/v4 v4.0.0
	github.com/julienschmidt/httprouter v1.3.0
	github.com/labstack/echo/v4 v4.5.0
	github.com/toqueteos/webbrowser v1.2.0
	golang.org/x/oauth2 v0.0.0-20210819190943-2bc19b11175f
)

replace github.com/crossid/crossid-go => ../
