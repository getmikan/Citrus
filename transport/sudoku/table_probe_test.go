package sudoku

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"

	sudokuobfs "github.com/metacubex/mihomo/transport/sudoku/obfs/sudoku"
)

// dribbleReader returns one byte per Read, up to limit bytes.
type dribbleReader struct {
	b     byte
	limit int
	reads int
}

func (r *dribbleReader) Read(p []byte) (int, error) {
	if r.reads >= r.limit {
		return 0, io.EOF
	}
	r.reads++
	p[0] = r.b
	return 1, nil
}

// A client that dribbles padding a byte at a time keeps every table
// undecided; the probe gives up once it has decoded its budget instead of
// decoding the growing probe again for every byte up to maxProbeBytes.
func TestSelectTableByProbeBoundsWork(t *testing.T) {
	t1, err := sudokuobfs.NewTableWithCustom("probe-seed", "prefer_entropy", "xpxvvpvv")
	if err != nil {
		t.Fatal(err)
	}
	t2, err := sudokuobfs.NewTableWithCustom("probe-seed", "prefer_entropy", "vxpvxvvp")
	if err != nil {
		t.Fatal(err)
	}
	var pad byte
	found := false
	for _, b := range t1.PaddingPool {
		if bytes.IndexByte(t2.PaddingPool, b) >= 0 {
			pad, found = b, true
			break
		}
	}
	if !found {
		t.Skip("the tables share no padding byte")
	}

	cfg := DefaultConfig()
	cfg.Key = "probe-test-key"
	cfg.AEADMethod = "chacha20-poly1305"
	cfg.Tables = []*sudokuobfs.Table{t1, t2}

	const limit = 8 * 1024
	r := &dribbleReader{b: pad, limit: limit}
	_, _, err = selectTableByProbe(bufio.NewReader(r), cfg, cfg.Tables)
	if err == nil {
		t.Fatal("padding selected a table")
	}
	if !strings.Contains(err.Error(), "decoded bytes") || r.reads >= limit {
		t.Fatalf("probe read %d bytes and ended with %v, want the work budget to end it", r.reads, err)
	}
}
