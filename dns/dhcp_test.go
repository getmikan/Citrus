package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/iface"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loopbackIface returns the name and IPv4 prefix of the loopback interface,
// so dhcpClient can pass its interface check without any real DHCP traffic.
func loopbackIface(t *testing.T) (string, netip.Prefix) {
	t.Helper()
	ifaces, err := iface.Interfaces()
	require.NoError(t, err)
	for name, ifaceObj := range ifaces {
		if ifaceObj.Flags&net.FlagLoopback == 0 || ifaceObj.Flags&net.FlagUp == 0 {
			continue
		}
		if addr, err := ifaceObj.PickIPv4Addr(netip.Addr{}); err == nil {
			return name, addr
		}
	}
	t.Skip("no loopback interface with an IPv4 address")
	return "", netip.Prefix{}
}

// stubDHCPFetch replaces the DHCP exchange for the duration of the test.
func stubDHCPFetch(t *testing.T, fn func(ctx context.Context, ifaceName string) ([]netip.Addr, error)) {
	t.Helper()
	orig := resolveDNSFromDHCP
	resolveDNSFromDHCP = fn
	t.Cleanup(func() { resolveDNSFromDHCP = orig })
}

// waitDHCPFetch waits for an in-flight fetch started by resolve to finish.
func waitDHCPFetch(t *testing.T, d *dhcpClient) {
	t.Helper()
	d.lock.Lock()
	done := d.done
	d.lock.Unlock()
	if done == nil {
		return
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("dhcp fetch did not finish")
	}
}

func TestDHCPClientClearsStaleIfaceError(t *testing.T) {
	name, addr := loopbackIface(t)
	stubDHCPFetch(t, func(context.Context, string) ([]netip.Addr, error) {
		t.Error("no fetch expected while the DHCP result is still valid")
		return nil, errors.New("unexpected fetch")
	})

	stub := []dnsClient{rcodeClient{addr: "rcode://success"}}
	d := newDHCPClient(name)
	d.ifaceAddr = addr
	d.dnsInvalidate = time.Now().Add(time.Hour)
	d.clients = stub
	d.ifaceErr = iface.ErrIfaceNotFound // left by an earlier outage

	clients, err := d.resolve(context.Background())
	require.NoError(t, err)
	assert.Equal(t, stub, clients)
	assert.NoError(t, d.ifaceErr)
}

func TestDHCPClientReportsIfaceError(t *testing.T) {
	stubDHCPFetch(t, func(context.Context, string) ([]netip.Addr, error) {
		t.Error("no fetch expected for a missing interface")
		return nil, errors.New("unexpected fetch")
	})

	stub := []dnsClient{rcodeClient{addr: "rcode://success"}}
	d := newDHCPClient("citrus-test-missing-iface")
	d.clients = stub

	_, err := d.resolve(context.Background())
	assert.ErrorIs(t, err, iface.ErrIfaceNotFound)
}

func TestDHCPClientRetryAfterFailedFetch(t *testing.T) {
	name, _ := loopbackIface(t)
	fetchErr := errors.New("no DHCP answer")
	stubDHCPFetch(t, func(context.Context, string) ([]netip.Addr, error) {
		return nil, fetchErr
	})

	d := newDHCPClient(name)
	before := time.Now()
	_, err := d.resolve(context.Background())
	assert.ErrorIs(t, err, fetchErr)
	waitDHCPFetch(t, d)

	// A failed discovery is retried soon instead of cached for DHCPTTL.
	d.lock.Lock()
	assert.WithinRange(t, d.dnsInvalidate, before.Add(IfaceTTL), time.Now().Add(IfaceTTL))
	d.lock.Unlock()
}

func TestDHCPClientRefetchAfterAddrChangeDuringFetch(t *testing.T) {
	name, addr := loopbackIface(t)
	started := make(chan struct{})
	release := make(chan struct{})
	fetches := 0
	stubDHCPFetch(t, func(context.Context, string) ([]netip.Addr, error) {
		fetches++
		if fetches == 1 {
			close(started)
			<-release
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.53")}, nil
	})

	d := newDHCPClient(name)
	resolved := make(chan error, 1)
	go func() {
		_, err := d.resolve(context.Background())
		resolved <- err
	}()
	<-started

	// The interface moves to another network while the fetch is running.
	d.lock.Lock()
	d.ifaceAddr = netip.MustParsePrefix("198.51.100.1/24")
	d.lock.Unlock()
	close(release)
	require.NoError(t, <-resolved)

	d.lock.Lock()
	assert.True(t, d.dnsInvalidate.IsZero(), "stale result must be refetched")
	d.ifaceInvalidate = time.Time{}
	d.lock.Unlock()

	_, err := d.resolve(context.Background())
	require.NoError(t, err)
	waitDHCPFetch(t, d)
	assert.Equal(t, 2, fetches)
	assert.Equal(t, addr, d.ifaceAddr)
}
