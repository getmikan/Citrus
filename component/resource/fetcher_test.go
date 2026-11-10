package resource

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	P "github.com/metacubex/mihomo/constant/provider"
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

// countingVehicle serves a new payload on every read.
type countingVehicle struct{ n atomic.Int64 }

func (v *countingVehicle) Read(_ context.Context, oldHash utils.HashType) ([]byte, utils.HashType, error) {
	buf := []byte(strconv.FormatInt(v.n.Add(1), 10))
	return buf, utils.MakeHash(buf), nil
}
func (v *countingVehicle) Write([]byte) error  { return nil }
func (v *countingVehicle) Path() string        { return "" }
func (v *countingVehicle) Url() string         { return "" }
func (v *countingVehicle) Proxy() string       { return "" }
func (v *countingVehicle) Type() P.VehicleType { return P.HTTP }

// TestFetcherConcurrentUpdates updates a fetcher from several goroutines (the
// API) while its pull loop runs and its state is read, as the controller does
// on PUT /providers/...; run with -race.
func TestFetcherConcurrentUpdates(t *testing.T) {
	var parsed atomic.Int64
	f := NewFetcher("concurrent", time.Millisecond, &countingVehicle{}, nil, func(buf []byte) (string, error) {
		parsed.Add(1)
		return string(buf), nil
	}, nil)
	defer f.Close()
	if _, err := f.Initial(); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if _, _, err := f.Update(); err != nil {
					t.Error(err)
					return
				}
				_ = f.UpdatedAt()
			}
		}()
	}
	wg.Wait()
	if parsed.Load() < 201 {
		t.Fatalf("parsed %d payloads, want at least 201", parsed.Load())
	}
}
