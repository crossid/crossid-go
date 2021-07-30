package jwt_mw

import (
	"fmt"
	"net/http"
	"testing"
)

func TestBearerTokenFromRequest(t *testing.T) {
	for k, tc := range []struct {
		h     http.Header
		tok   string
		err   bool
		exist bool
	}{
		{
			h:     http.Header{BearerHeaderKey: {"Bearer jwt"}},
			tok:   "jwt",
			exist: true,
		},
		{
			// header is case sensitive
			h:     http.Header{"authorization": {"Bearer jwt"}},
			tok:   "",
			exist: false,
		},
		{
			// bearer is in case sensitive
			h:     http.Header{BearerHeaderKey: {"BeAReR jwt"}},
			tok:   "jwt",
			exist: true,
		},
		{
			h:   http.Header{BearerHeaderKey: {"wrong jwt"}},
			err: true,
		},
		{
			h: http.Header{BearerHeaderKey: {}},
		},
		{
			h:   http.Header{BearerHeaderKey: {"jwt"}},
			err: true,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			tok, err := BearerTokenFromRequest(&http.Request{Header: tc.h})

			if !tc.err && err != nil {
				t.Errorf("unexpected error")
			}

			if tc.err && err == nil {
				t.Errorf("expected error")
			}

			if tc.tok != tok {
				t.Errorf("tokens are not equal: %s != %s", tc.tok, tok)
			}

			if tc.exist && tok == "" {
				t.Errorf("expected token to exist")
			}
		})
	}
}
