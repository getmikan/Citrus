package tunnel

import (
	"fmt"
	"os"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	RC "github.com/metacubex/mihomo/rules/common"

	"github.com/stretchr/testify/require"
)

// reentrantRule stands in for a rule that resolves the host while matching
// with dns.respect-rules: the DNS dial calls back into match. Before calling
// it, the rule waits until a config writer is queued on configMux.
type reentrantRule struct {
	RC.Base
	entered      chan struct{}
	writerQueued <-chan struct{}
}

func (r *reentrantRule) RuleType() C.RuleType { return C.Domain }
func (r *reentrantRule) Adapter() string      { return "DIRECT" }
func (r *reentrantRule) Payload() string      { return "reentrant" }
func (r *reentrantRule) Match(md *C.Metadata, _ C.RuleMatchHelper) (bool, string) {
	if md.Host != "outer.test" {
		return false, ""
	}
	close(r.entered)
	<-r.writerQueued
	_, _, _ = match(&C.Metadata{NetWork: C.TCP, Host: "dns.test", DstPort: 443}, C.RuleMatchHelper{})
	return true, "DIRECT"
}

func TestMatchReentryWithQueuedWriter(t *testing.T) {
	setupReplaceRules(t)
	entered, writerQueued := make(chan struct{}), make(chan struct{})
	UpdateRules([]C.Rule{&reentrantRule{entered: entered, writerQueued: writerQueued}}, nil, nil)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = match(&C.Metadata{NetWork: C.TCP, Host: "outer.test", DstPort: 443}, C.RuleMatchHelper{})
	}()
	<-entered
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		UpdateRules(Rules(), nil, nil)
	}()
	// give the writer time to queue on configMux behind a held read lock
	time.Sleep(50 * time.Millisecond)
	close(writerQueued)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		// The outer match, the writer and the cleanup would all stay
		// blocked on configMux, so stop the binary instead of hanging.
		fmt.Fprintln(os.Stderr, "FAIL: match re-entered from a rule blocked behind a queued config writer")
		os.Exit(1)
	}
	<-writerDone
	require.NotNil(t, Rules())
}
