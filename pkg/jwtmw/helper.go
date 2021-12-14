package jwtmw

import (
	"context"
	"fmt"
	"github.com/crossid/crossid-go/pkg/x/stringslice"
)

func ScopesCheckerOR(_ context.Context, required, candidates []string) error {
	if len(required) == 0 {
		return nil
	}
	for _, r := range required {
		if stringslice.IndexOf(candidates, r) > -1 {
			return nil
		}
	}

	return ErrMissingClaim
}

func scopesCheckerAND(_ context.Context, required, candidates []string) error {
	for _, r := range required {
		f := false
		if stringslice.IndexOf(candidates, r) > -1 {
			f = true
		}
		if !f {
			return fmt.Errorf("not found")
		}
	}

	return nil
}
