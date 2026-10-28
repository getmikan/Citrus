package dns

import (
	"testing"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ca/catest"

	"github.com/metacubex/tls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDoHProbeKeepsVerification(t *testing.T) {
	pki := catest.New(t)
	pki.Trust(t)
	probe := func(nameCertVerify string) error {
		tlsConfig, err := ca.GetTLSConfig(ca.Option{
			TLSConfig:      &tls.Config{ServerName: catest.ServerName, MinVersion: tls.VersionTLS12},
			NameCertVerify: nameCertVerify,
		})
		require.NoError(t, err)
		return pki.Handshake(t, probeTLSConfig(tlsConfig))
	}
	assert.NoError(t, probe(""))
	assert.NoError(t, probe(catest.ServerName))
	// name-cert-verify skips the default verification, the probe must not accept any certificate
	assert.Error(t, probe("other.example.test"))
}
