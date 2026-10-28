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

// expireDHCPChecks makes the next resolve recheck the interface and refetch
// as if both TTLs had passed.
func expireDHCPChecks(d *dhcpClient) {
	d.lock.Lock()
	d.ifaceInvalidate = time.Time{}
	d.dnsInvalidate = time.Time{}
	d.lock.Unlock()
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

func TestDHCPClientRetryBackoff(t *testing.T) {
	name, _ := loopbackIface(t)
	fetchErr := errors.New("no DHCP answer")
	var result []netip.Addr
	var resultErr error
	fetches := 0
	stubDHCPFetch(t, func(context.Context, string) ([]netip.Addr, error) {
		fetches++
		return result, resultErr
	})

	d := newDHCPClient(name)
	resultErr = fetchErr

	want := []time.Duration{IfaceTTL, 2 * IfaceTTL, 4 * IfaceTTL}
	for i, delay := range want {
		before := time.Now()
		_, err := d.resolve(context.Background())
		waitDHCPFetch(t, d)
		if i == 0 {
			// The first call waits for the fetch and gets its error.
			assert.ErrorIs(t, err, fetchErr)
		}
		d.lock.Lock()
		assert.Equal(t, delay, d.retryDelay)
		assert.WithinRange(t, d.dnsInvalidate, before.Add(delay), time.Now().Add(delay))
		d.lock.Unlock()
		expireDHCPChecks(d)
	}
	assert.Equal(t, len(want), fetches)

	// The backoff is capped at DHCPTTL.
	assert.Equal(t, DHCPTTL, nextDHCPRetryDelay(DHCPTTL/2+time.Second))
	assert.Equal(t, DHCPTTL, nextDHCPRetryDelay(DHCPTTL))

	// A successful fetch resets the backoff and caches for DHCPTTL.
	result, resultErr = []netip.Addr{netip.MustParseAddr("192.0.2.53")}, nil
	before := time.Now()
	_, _ = d.resolve(context.Background())
	waitDHCPFetch(t, d)
	clients, err := d.resolve(context.Background())
	require.NoError(t, err)
	require.Len(t, clients, 1)
	assert.Equal(t, "udp://192.0.2.53:53", clients[0].Address())
	d.lock.Lock()
	assert.Zero(t, d.retryDelay)
	assert.False(t, d.dnsInvalidate.Before(before.Add(DHCPTTL)))
	d.lock.Unlock()
}

func TestDHCPClientRetryBackoffResetOnAddrChange(t *testing.T) {
	name, addr := loopbackIface(t)
	stubDHCPFetch(t, func(context.Context, string) ([]netip.Addr, error) {
		t.Error("no fetch expected while backing off")
		return nil, errors.New("unexpected fetch")
	})

	d := newDHCPClient(name)
	d.ifaceAddr = netip.MustParsePrefix("198.51.100.1/24") // previous network
	d.dnsInvalidate = time.Now().Add(time.Hour)
	d.retryDelay = 8 * IfaceTTL
	d.err = errors.New("no DHCP answer")

	d.lock.Lock()
	_, err := d.invalidate()
	d.lock.Unlock()
	require.NoError(t, err)
	assert.Zero(t, d.retryDelay)
	assert.Equal(t, addr, d.ifaceAddr)
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
