package httpmask

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func setUploadBudget(t *testing.T, n int) {
	t.Helper()
	old := maxBufferedUploadBytes
	maxBufferedUploadBytes = n
	t.Cleanup(func() { maxBufferedUploadBytes = old })
}

func TestUploadBudgetIsSharedAcrossSessions(t *testing.T) {
	setUploadBudget(t, 2*uploadBufferReservation)
	setUploadLimits(t, 8, time.Minute)
	for _, mode := range []string{"stream", "poll"} {
		t.Run(mode, func(t *testing.T) {
			s := NewTunnelServer(TunnelServerOptions{Mode: "auto"})
			token1, conn1 := openTestSession(t, s)
			defer conn1.Close()
			token2, conn2 := openTestSession(t, s)
			defer conn2.Close()
			u1 := startStalledUpload(t, s, mode, token1)
			startStalledUpload(t, s, mode, token2)
			waitUploads(t, s, token1, 1)
			waitUploads(t, s, token2, 1)
			rejected := startStalledUpload(t, s, mode, token2)
			rejected.waitDone(t, time.Second, "global upload budget")
			if got := <-rejected.status; got != http.StatusServiceUnavailable {
				t.Fatalf("over-budget response = %d, want 503", got)
			}
			u1.client.Close()
			u1.waitDone(t, time.Second, "upload cancellation")
			waitUploads(t, s, token1, 0)
			startStalledUpload(t, s, mode, token2)
			waitUploads(t, s, token2, 2)
		})
	}
}

func TestSessionCloseKeepsReservationUntilUploadExits(t *testing.T) {
	setUploadBudget(t, uploadBufferReservation)
	s := NewTunnelServer(TunnelServerOptions{Mode: "stream"})
	token, tunnel := openTestSession(t, s)
	defer tunnel.Close()
	sess, ok := s.sessionGet(token)
	if !ok {
		t.Fatal("missing session")
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if !s.beginSessionUpload(token, sess, a) {
		t.Fatal("upload refused")
	}
	if s.beginSessionUpload(token, sess, a) {
		t.Fatal("duplicate registration accepted")
	}
	s.sessionClose(token)
	if s.uploadBytes != uploadBufferReservation {
		t.Fatal("session close released live upload budget")
	}
	s.endSessionUpload(sess, a)
	s.endSessionUpload(sess, a)
	if s.uploadBytes != 0 {
		t.Fatal("upload completion leaked or double-released budget")
	}
}

func TestPollUploadRejectsOversizedBody(t *testing.T) {
	s := NewTunnelServer(TunnelServerOptions{Mode: "auto"})
	token, tunnel := openTestSession(t, s)
	defer tunnel.Close()
	a, b := net.Pipe()
	defer a.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.pollPush(b, token, 1, bytes.NewReader(bytes.Repeat([]byte{'\n'}, maxUploadBytes+1)))
	}()
	_ = a.SetReadDeadline(time.Now().Add(time.Second))
	response, err := io.ReadAll(a)
	if err != nil {
		t.Fatal(err)
	}
	<-done
	if !bytes.Contains(response, []byte("413")) {
		t.Fatalf("unexpected response: %s", response)
	}
	if s.uploadBytes != 0 {
		t.Fatal("oversized upload leaked budget")
	}
}
