package main

import (
	"bufio"
	"io"
	"os"
	"regexp"
)

// visionCount: how many tunnels of a phase switched Vision to direct copy.
type visionCount struct {
	Streams    int `json:"streams"`
	UpDirect   int `json:"up_direct"`
	DownDirect int `json:"down_direct"`
}

// Xray's debug log (v26): "... [Debug] [<session>] proxy: XtlsPadding
// <content> <padding> <command>" for every padded write of the client's
// upload, "... [Debug] [<session>] proxy: Xtls Unpadding new block, content
// <n> padding <n> command <c>" for every padded block of the download it
// reads. Command 2 (CommandPaddingDirect) is the last padded block before
// direct copy.
var (
	visionPadRe   = regexp.MustCompile(`\[(\d+)\] proxy: XtlsPadding \d+ \d+ (\d)`)
	visionUnpadRe = regexp.MustCompile(`\[(\d+)\] proxy: Xtls Unpadding new block, content \d+ padding \d+ command (\d)`)
)

func fileSize(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Size()
}

// visionFromLog reads the Xray client log from offset on and counts the
// sessions with a padded upload (every Vision tunnel starts padded) and
// those of them whose upload and download went direct.
func visionFromLog(path string, offset int64) (*visionCount, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	up, down := map[string]bool{}, map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if m := visionPadRe.FindStringSubmatch(line); m != nil {
			up[m[1]] = up[m[1]] || m[2] == "2"
		} else if m := visionUnpadRe.FindStringSubmatch(line); m != nil {
			down[m[1]] = down[m[1]] || m[2] == "2"
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	v := &visionCount{Streams: len(up)}
	for s, direct := range up {
		if direct {
			v.UpDirect++
		}
		if down[s] {
			v.DownDirect++
		}
	}
	return v, nil
}
