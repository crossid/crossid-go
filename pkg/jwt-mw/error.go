package jwt_mw

import "fmt"

var (
	ErrExtractingToken = fmt.Errorf("error extracting token")
	ErrMissingToken    = fmt.Errorf("missing token")
	ErrInvalidToken    = fmt.Errorf("invalid token")
)
