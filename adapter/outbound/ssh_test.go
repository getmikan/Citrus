package outbound

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strings"
	"testing"

	"github.com/metacubex/ssh"
	"github.com/stretchr/testify/require"
)

func newTestSSHKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	return key
}

func TestSshHostKey(t *testing.T) {
	pinned := newTestSSHKey(t)
	other := newTestSSHKey(t)
	remote := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 22}
	base := SshOption{Name: "ssh", Server: "192.0.2.1", Port: 22, UserName: "u", Password: "p"}

	opt := base
	opt.HostKey = []string{strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pinned)))}
	s, err := NewSsh(opt)
	require.NoError(t, err)
	require.NoError(t, s.config.HostKeyCallback("192.0.2.1:22", remote, pinned))
	require.Error(t, s.config.HostKeyCallback("192.0.2.1:22", remote, other))

	// Without host-key the server key is accepted as before (with a warning),
	// and skip-host-key-check only silences the warning.
	for _, skip := range []bool{false, true} {
		opt = base
		opt.SkipHostKeyCheck = skip
		s, err = NewSsh(opt)
		require.NoError(t, err)
		require.NoError(t, s.config.HostKeyCallback("192.0.2.1:22", remote, other))
	}

	opt = base
	opt.HostKey = []string{"not a key"}
	_, err = NewSsh(opt)
	require.ErrorContains(t, err, "parse host key 0")
}
