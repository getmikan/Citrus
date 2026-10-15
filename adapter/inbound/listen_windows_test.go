package inbound

import (
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/wireguard-go/ipc/namedpipe"
	"golang.org/x/sys/windows"
)

func currentUserSID(t *testing.T) string {
	t.Helper()
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("GetTokenUser: %v", err)
	}
	return tokenUser.User.Sid.String()
}

func TestDefaultNamedPipeSDDL(t *testing.T) {
	sid := currentUserSID(t)
	sddl, err := defaultNamedPipeSDDL()
	if err != nil {
		t.Fatalf("defaultNamedPipeSDDL: %v", err)
	}
	if !strings.Contains(sddl, ";;;"+sid+")") {
		t.Errorf("SDDL %q does not grant the current user %s", sddl, sid)
	}
	for _, forbidden := range []string{";;;BU)", ";;;WD)", ";;;AU)", ";;;IU)", ";;;AN)"} {
		if strings.Contains(sddl, forbidden) {
			t.Errorf("SDDL %q grants access to %s", sddl, strings.Trim(forbidden, ";)"))
		}
	}
	if !strings.HasPrefix(sddl, "D:P") {
		t.Errorf("SDDL %q must have a protected DACL", sddl)
	}
	if _, err := windows.SecurityDescriptorFromString(sddl); err != nil {
		t.Errorf("SDDL %q is not valid: %v", sddl, err)
	}
}

func TestListenNamedPipeOwnerCanConnect(t *testing.T) {
	t.Setenv(NamedPipeSDDLEnv, "")
	path := fmt.Sprintf(`\\.\pipe\citrus-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
	l, err := ListenNamedPipe(path)
	if err != nil {
		t.Fatalf("ListenNamedPipe: %v", err)
	}
	defer l.Close()

	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("ok"))
		_ = c.Close()
	}()

	c, err := namedpipe.DialTimeout(path, 5*time.Second)
	if err != nil {
		t.Fatalf("dial as owner: %v", err)
	}
	defer c.Close()
	buf, err := io.ReadAll(c)
	if err != nil || string(buf) != "ok" {
		t.Fatalf("read = %q, %v", buf, err)
	}
}
