package inbound

import (
	"fmt"
	"net"
	"os"

	"github.com/metacubex/wireguard-go/ipc/namedpipe"
	"golang.org/x/sys/windows"
)

const SupportNamedPipe = true

// NamedPipeSDDLEnv overrides the security descriptor set on the namedpipe.
const NamedPipeSDDLEnv = "LISTEN_NAMEDPIPE_SDDL"

// namedPipeSDDL builds the default Security Descriptor for the namedpipe.
// It grants full access to the given user (the account the core runs as),
// the local system and the built-in administrators, and nobody else.
// The DACL is protected (P), so nothing is inherited from the parent.
func namedPipeSDDL(userSID string) string {
	return fmt.Sprintf("D:P(A;;GA;;;%s)(A;;GA;;;SY)(A;;GA;;;BA)", userSID)
}

// defaultNamedPipeSDDL returns the default SDDL for the account of the current process.
func defaultNamedPipeSDDL() (string, error) {
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("get current process user: %w", err)
	}
	return namedPipeSDDL(tokenUser.User.Sid.String()), nil
}

func ListenNamedPipe(path string) (net.Listener, error) {
	sddl := os.Getenv(NamedPipeSDDLEnv)
	if sddl == "" {
		var err error
		sddl, err = defaultNamedPipeSDDL()
		if err != nil {
			return nil, err
		}
	}
	securityDescriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}
	namedpipeLC := namedpipe.ListenConfig{
		SecurityDescriptor: securityDescriptor,
		InputBufferSize:    256 * 1024,
		OutputBufferSize:   256 * 1024,
	}
	return namedpipeLC.Listen(path)
}
