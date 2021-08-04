package stringslice

import (
	"github.com/crossid/crossid-go/pkg/x/testx"
	"testing"
)

func TestIndex(t *testing.T) {
	arr := []string{"a", "b"}
	testx.AssertTrue(t, Index(len(arr), func(i int) bool {
		return arr[i] == "a"
	}) == 0, "")
	testx.AssertTrue(t, Index(len(arr), func(i int) bool {
		return arr[i] == "b"
	}) == 1, "")
	testx.AssertTrue(t, Index(len(arr), func(i int) bool {
		return arr[i] == "c"
	}) == -1, "")
}

func TestIndexOf(t *testing.T) {
	arr := []string{"a", "b"}
	testx.AssertTrue(t, IndexOf(arr, "a") == 0, "")
	testx.AssertTrue(t, IndexOf(arr, "b") == 1, "")
	testx.AssertTrue(t, IndexOf(arr, "c") == -1, "")
}
