package outbound

import (
	"context"
	"errors"
	"net"
	"runtime"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

func newTestWireGuard(t *testing.T, name string, port int) *WireGuard {
	t.Helper()
	option := WireGuardOption{
		Name:       name,
		Ip:         "10.9.0.2",
		PrivateKey: "4F7zVRZpPEAHIEFBcZj4NITwyiXwzHHbRMpRlZr9bnk=",
		UDP:        true,
	}
	option.Server = "127.0.0.1"
	option.Port = port
	option.PublicKey = "rsPXORPczwaVYfkc29uC6p2Vcjh2POFmL+quiQbBezk="
	w, err := NewWireGuard(option)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}

func initTestWireGuard(t *testing.T, w *WireGuard) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return w.init(ctx)
}

// wireGuardDeviceClosed doesn't wait, because closing the device is synchronous.
func wireGuardDeviceClosed(w *WireGuard) bool {
	select {
	case <-w.device.(interface{ Wait() chan struct{} }).Wait():
		return true
	default:
		return false
	}
}

// listenTestPeer returns a local UDP port that silently absorbs the handshakes.
func listenTestPeer(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func TestWireGuardTakeOverDevice(t *testing.T) {
	port := listenTestPeer(t)

	// the same proxy parsed by three config reloads
	old := newTestWireGuard(t, "wg", port)
	late := newTestWireGuard(t, "wg", port)
	current := newTestWireGuard(t, "wg", port)

	if err := initTestWireGuard(t, old); err != nil {
		t.Fatal(err)
	}
	if err := initTestWireGuard(t, current); err != nil {
		t.Fatal(err)
	}
	if !wireGuardDeviceClosed(old) {
		t.Fatal("device of the outdated outbound is still running")
	}

	// an outdated outbound started later must not take the device back
	if err := initTestWireGuard(t, late); !errors.Is(err, errWireGuardOutdated) {
		t.Fatalf("expected %v, got %v", errWireGuardOutdated, err)
	}
	if wireGuardDeviceClosed(current) {
		t.Fatal("device of the current outbound was closed")
	}

	_ = current.Close()
	wireGuardDevicesMutex.Lock()
	_, exist := wireGuardDevices[current.deviceKey()]
	wireGuardDevicesMutex.Unlock()
	if exist {
		t.Fatal("closed outbound still holds its device key")
	}
}

func TestWireGuardKeepDeviceOfOtherProxy(t *testing.T) {
	port := listenTestPeer(t)

	// different proxies that share a key are left alone
	a := newTestWireGuard(t, "wg-a", port)
	b := newTestWireGuard(t, "wg-b", port)

	if err := initTestWireGuard(t, a); err != nil {
		t.Fatal(err)
	}
	if err := initTestWireGuard(t, b); err != nil {
		t.Fatal(err)
	}
	if wireGuardDeviceClosed(a) || wireGuardDeviceClosed(b) {
		t.Fatal("device of another proxy was closed")
	}
}

// testProxy stands in for adapter.Proxy, which can't be imported here.
type testProxy struct {
	C.Proxy
	adapter C.ProxyAdapter
}

func (p testProxy) Adapter() C.ProxyAdapter { return p.adapter }

func TestWireGuardCloseRemovedDevices(t *testing.T) {
	port := listenTestPeer(t)

	// first config: proxies "kept" and "removed", both in use
	kept := newTestWireGuard(t, "kept", port)
	removed := newTestWireGuard(t, "removed", port)
	for _, w := range []*WireGuard{kept, removed} {
		if err := initTestWireGuard(t, w); err != nil {
			t.Fatal(err)
		}
	}

	// second config: only "kept" is parsed again, and its new outbound isn't used yet
	keptNew := newTestWireGuard(t, "kept", port)
	serial := WireGuardSerial()
	// a provider update after ApplyConfig took the serial
	later := newTestWireGuard(t, "later", port)
	if err := initTestWireGuard(t, later); err != nil {
		t.Fatal(err)
	}

	// the config keeps the wrapper alive, otherwise its finalizer closes keptNew
	keptNewProxy := testProxy{adapter: NewAutoCloseProxyAdapter(keptNew)}
	defer runtime.KeepAlive(keptNewProxy)
	CloseWireGuardDevicesExcept(serial, []C.Proxy{keptNewProxy})

	if !wireGuardDeviceClosed(removed) {
		t.Fatal("device of the removed proxy is still running")
	}
	if !wireGuardDeviceClosed(kept) {
		t.Fatal("device of the replaced outbound is still running")
	}
	if wireGuardDeviceClosed(later) {
		t.Fatal("device of an outbound created after the serial was closed")
	}
	if err := initTestWireGuard(t, keptNew); err != nil {
		t.Fatal(err)
	}
	if wireGuardDeviceClosed(keptNew) {
		t.Fatal("device of the current outbound was closed")
	}
}
