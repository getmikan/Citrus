package route

import (
	"context"
	"fmt"
	stdnet "net"
	"os"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"

	"github.com/metacubex/http"
	"github.com/metacubex/wireguard-go/ipc/namedpipe"
)

func TestNamedPipeEnforcesSecret(t *testing.T) {
	t.Setenv(inbound.NamedPipeSDDLEnv, "")
	path := fmt.Sprintf(`\\.\pipe\citrus-route-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
	l, err := inbound.ListenNamedPipe(path)
	if err != nil {
		t.Fatalf("ListenNamedPipe: %v", err)
	}
	server := &http.Server{Handler: newHandler(&Config{Secret: testSecret})}
	go func() { _ = server.Serve(l) }()
	defer server.Close()

	dial := func(ctx context.Context) (stdnet.Conn, error) {
		return namedpipe.DialContext(ctx, path)
	}
	if code := getStatus(t, dial, ""); code != http.StatusUnauthorized {
		t.Errorf("pipe GET / without token: got %d, want %d", code, http.StatusUnauthorized)
	}
	if code := getStatus(t, dial, testSecret); code != http.StatusOK {
		t.Errorf("pipe GET / with token: got %d, want %d", code, http.StatusOK)
	}
}
