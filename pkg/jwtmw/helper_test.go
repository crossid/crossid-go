package jwtmw

import (
	"context"
	"testing"
)

func TestScopesCheckerOR(t *testing.T) {
	for k, tc := range []struct {
		name string
		r    []string
		c    []string
		v    bool
	}{
		{
			name: "exact - single",
			r:    []string{"a"},
			c:    []string{"a"},
			v:    true,
		},
		{
			name: "exact - multi unsorted",
			r:    []string{"a", "b"},
			c:    []string{"b", "a"},
			v:    true,
		},
		{
			name: "contains - single first",
			r:    []string{"a", "b"},
			c:    []string{"a"},
			v:    true,
		},
		{
			name: "contains - single next",
			r:    []string{"a", "b", "c"},
			c:    []string{"b"},
			v:    true,
		},
		{
			name: "contains - single last",
			r:    []string{"a", "b", "c"},
			c:    []string{"c"},
			v:    true,
		},
		{
			name: "contains - multiple",
			r:    []string{"a", "b", "c"},
			c:    []string{"d", "v", "a"},
			v:    true,
		},
		{
			name: "non required",
			r:    []string{},
			c:    []string{},
			v:    true,
		},
		{
			name: "empty claims",
			r:    []string{"a"},
			c:    []string{},
			v:    false,
		},
		{
			name: "no match - single",
			r:    []string{"a"},
			c:    []string{"c"},
			v:    false,
		},
		{
			name: "no match - multi required",
			r:    []string{"a", "b"},
			c:    []string{"c"},
			v:    false,
		},
		{
			name: "no match - multi",
			r:    []string{"a", "b"},
			c:    []string{"c", "d"},
			v:    false,
		},
	} {
		err := ScopesCheckerOR(context.Background(), tc.r, tc.c)
		if tc.v {
			if err != nil {
				t.Errorf("case %d=%s expected to be valid but got: %s", k, tc.name, err)
			}
		} else {
			if err == nil {
				t.Errorf("case %d=%s expected error but got nil", k, tc.name)
			}
		}
	}
}

func TestScopesCheckerAND(t *testing.T) {
	for k, tc := range []struct {
		name string
		r    []string
		c    []string
		v    bool
	}{
		{
			name: "exact - single",
			r:    []string{"a"},
			c:    []string{"a"},
			v:    true,
		},
		{
			name: "exact - multi sorted",
			r:    []string{"a", "b"},
			c:    []string{"a", "b"},
			v:    true,
		},
		{
			name: "exact - multi unsorted",
			r:    []string{"a", "b"},
			c:    []string{"b", "a"},
			v:    true,
		},
		{
			name: "contains - sorted",
			r:    []string{"a", "b"},
			c:    []string{"a", "b", "a"},
			v:    true,
		},
		{
			name: "contains - unsorted",
			r:    []string{"a", "b"},
			c:    []string{"c", "b", "a"},
			v:    true,
		},
		{
			name: "contains - many",
			r:    []string{"a", "b", "c", "d", "e"},
			c:    []string{"z", "x", "a", "v", "b", "c", "e", "d"},
			v:    true,
		},
		{
			name: "empty - both",
			r:    []string{},
			c:    []string{},
			v:    true,
		},
		{
			name: "empty - required",
			r:    []string{},
			c:    []string{"a", "b"},
			v:    true,
		},
		{
			name: "empty - current",
			r:    []string{"a", "b"},
			c:    []string{},
		},
		{
			name: "no match - single",
			r:    []string{"a"},
			c:    []string{"b"},
		},
		{
			name: "no match - multi required (first exists)",
			r:    []string{"a", "b"},
			c:    []string{"a"},
		},
		{
			name: "no match - multi required (last exists)",
			r:    []string{"a", "b"},
			c:    []string{"b"},
		},
		{
			name: "no match - many",
			r:    []string{"a", "b", "c", "d", "e", "f"},
			c:    []string{"f", "e", "d", "c", "b", "Z"},
		},
	} {
		err := scopesCheckerAND(context.Background(), tc.r, tc.c)
		if tc.v {
			if err != nil {
				t.Errorf("case %d='%s' expected to be valid but got: %s", k, tc.name, err)
			}
		} else {
			if err == nil {
				t.Errorf("case %d='%s' expected error but got nil", k, tc.name)
			}
		}
	}
}
