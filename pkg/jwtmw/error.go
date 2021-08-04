package jwtmw

import "fmt"

var (
	ErrExtractingToken  = fmt.Errorf("error extracting token")
	ErrMissingToken     = fmt.Errorf("missing token")
	ErrInvalidToken     = fmt.Errorf("invalid token")
	ErrExtractingClaims = fmt.Errorf("error extracting claims")
	ErrMissingClaim     = fmt.Errorf("insufficient privileges")
)
