package sing_tun

import (
	"fmt"
	"io"
	"net"
	"syscall"
	"time"
	"unsafe"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/iface"

	"golang.org/x/sys/windows"
)

// mibIPInterfaceRow is MIB_IPINTERFACE_ROW from netioapi.h, laid out as in
// sing-tun's internal/winipcfg (from wireguard-windows). x/sys/windows has
// MibIpInterfaceRow, but it declares the 1-byte NL_INTERFACE_OFFLOAD_ROD
// fields as uint32, which shifts DisableDefaultRoutes and the size.
// The explicit padding puts InterfaceLUID at offset 8 on 386 as well, where
// Go aligns uint64 to 4 bytes and MSVC to 8.
type mibIPInterfaceRow struct {
	Family                               uint16
	_                                    [6]byte
	InterfaceLUID                        uint64
	InterfaceIndex                       uint32
	MaxReassemblySize                    uint32
	InterfaceIdentifier                  uint64
	MinRouterAdvertisementInterval       uint32
	MaxRouterAdvertisementInterval       uint32
	AdvertisingEnabled                   bool
	ForwardingEnabled                    bool
	WeakHostSend                         bool
	WeakHostReceive                      bool
	UseAutomaticMetric                   bool
	UseNeighborUnreachabilityDetection   bool
	ManagedAddressConfigurationSupported bool
	OtherStatefulConfigurationSupported  bool
	AdvertiseDefaultRoute                bool
	RouterDiscoveryBehavior              int32
	DadTransmits                         uint32
	BaseReachableTime                    uint32
	RetransmitTime                       uint32
	PathMTUDiscoveryTimeout              uint32
	LinkLocalAddressBehavior             int32
	LinkLocalAddressTimeout              uint32
	ZoneIndices                          [16]uint32 // ScopeLevelCount
	SitePrefixLength                     uint32
	Metric                               uint32
	NLMTU                                uint32
	Connected                            bool
	SupportsWakeUpPatterns               bool
	SupportsNeighborDiscovery            bool
	SupportsRouterDiscovery              bool
	ReachableTime                        uint32
	TransmitOffload                      uint8
	ReceiveOffload                       uint8
	DisableDefaultRoutes                 bool
}

const mibIPInterfaceRowSize = 168 // sizeof(MIB_IPINTERFACE_ROW) on x86, x64 and arm64

// compile time check of the size: both array lengths must be non-negative
var (
	_ [mibIPInterfaceRowSize - unsafe.Sizeof(mibIPInterfaceRow{})]byte
	_ [unsafe.Sizeof(mibIPInterfaceRow{}) - mibIPInterfaceRowSize]byte
)

var (
	modIPHlpAPI                     = windows.NewLazySystemDLL("iphlpapi.dll")
	procInitializeIpInterfaceEntry  = modIPHlpAPI.NewProc("InitializeIpInterfaceEntry")
	procGetIpInterfaceEntry         = modIPHlpAPI.NewProc("GetIpInterfaceEntry")
	procConvertInterfaceIndexToLuid = modIPHlpAPI.NewProc("ConvertInterfaceIndexToLuid")
)

func ipHlpCall(proc *windows.LazyProc, args ...uintptr) error {
	if err := proc.Find(); err != nil {
		return err
	}
	r0, _, _ := syscall.SyscallN(proc.Addr(), args...)
	if r0 != 0 {
		return ipHlpError(syscall.Errno(r0))
	}
	return nil
}

func ipHlpError(errno syscall.Errno) error {
	switch errno {
	case windows.ERROR_NOT_FOUND, windows.ERROR_FILE_NOT_FOUND:
		return fmt.Errorf("%w: %w", errIPInterfaceGone, errno)
	case windows.ERROR_ACCESS_DENIED:
		return fmt.Errorf("%w: %w", errIPInterfaceDenied, errno)
	}
	return errno
}

// getIPInterfaceRow reads the row of luid and family. It only reads: the core
// never writes the row.
func getIPInterfaceRow(luid uint64, family uint16) (*mibIPInterfaceRow, error) {
	row := &mibIPInterfaceRow{}
	if err := procInitializeIpInterfaceEntry.Find(); err != nil {
		return nil, err
	}
	syscall.SyscallN(procInitializeIpInterfaceEntry.Addr(), uintptr(unsafe.Pointer(row)))
	row.InterfaceLUID = luid
	row.Family = family
	if err := ipHlpCall(procGetIpInterfaceEntry, uintptr(unsafe.Pointer(row))); err != nil {
		return nil, err
	}
	return row, nil
}

func interfaceIndexToLUID(index int) (uint64, error) {
	var luid uint64
	err := ipHlpCall(procConvertInterfaceIndexToLuid, uintptr(uint32(index)), uintptr(unsafe.Pointer(&luid)))
	return luid, err
}

func readIPInterfaceFlags(key ipInterfaceKey) (ipInterfaceFlags, error) {
	row, err := getIPInterfaceRow(key.LUID, key.Family)
	if err != nil {
		return ipInterfaceFlags{}, err
	}
	return ipInterfaceFlags{Forwarding: row.ForwardingEnabled, WeakHostSend: row.WeakHostSend}, nil
}

const (
	forwardingCheckDebounce = 300 * time.Millisecond
	forwardingCheckPoll     = 5 * time.Second
)

var forwardingCheckSystem = forwardingCheckEnv{
	readFlags:   readIPInterfaceFlags,
	indexToLUID: interfaceIndexToLUID,
	nameToLUID: func(name string) (uint64, error) {
		netInterface, err := net.InterfaceByName(name)
		if err != nil {
			return 0, err
		}
		return interfaceIndexToLUID(netInterface.Index)
	},
	boundInterface: func() (int, string) {
		if name := dialer.DefaultInterface.Load(); name != "" {
			if bound, err := iface.ResolveInterface(name); err == nil {
				return bound.Index, bound.Name
			}
		}
		return 0, ""
	},
	debounce: forwardingCheckDebounce,
	poll:     forwardingCheckPoll,
}

// startForwardingCheck watches Forwarding/WeakHostSend on the egress
// interfaces of a TUN with auto-route, see forwarding_check.go.
func startForwardingCheck(l *Listener) io.Closer {
	if !l.options.AutoRoute || l.networkUpdateMonitor == nil || l.defaultInterfaceMonitor == nil {
		return nil
	}
	c := newForwardingChecker(forwardingCheckSystem, l.tunName, l.options.AutoDetectInterface, l.networkUpdateMonitor, l.defaultInterfaceMonitor)
	c.start()
	return c
}
