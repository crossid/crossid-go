package testx

import "testing"

func AssertNoError(t *testing.T, err error) {
	if err != nil {
		t.Fatalf("expected no error but got %s", err)
	}
}

func AssertError(t *testing.T, err error) {
	if err == nil {
		t.Fatalf("expected an error")
	}
}

func AssertTrue(t *testing.T, v bool, msg string) {
	if !v {
		t.Fatalf(msg)
	}
}
