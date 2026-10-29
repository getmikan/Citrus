package resource

import (
	"testing"
	"time"
)

func TestFetcherParserPanicIsError(t *testing.T) {
	updated := false
	f := NewFetcher("panicky", time.Minute, nil, nil, func([]byte) (int, error) {
		var s []int
		return s[1], nil // index out of range, like a corrupt rule-set decoder
	}, func(int) { updated = true })
	defer f.ctxCancel()

	if _, _, err := f.SideUpdate([]byte("payload")); err == nil {
		t.Fatal("want error from a panicking parser")
	}
	if updated {
		t.Fatal("onUpdate must not run after a failed parse")
	}
}
