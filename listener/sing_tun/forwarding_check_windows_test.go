package sing_tun

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"unsafe"
)

// offsets of MIB_IPINTERFACE_ROW in the Windows SDK, the same on x86, x64 and
// arm64 (sing-tun internal/winipcfg/types_test.go)
func TestMibIPInterfaceRowLayout(t *testing.T) {
	var row mibIPInterfaceRow
	base := uintptr(unsafe.Pointer(&row))
	offsets := []struct {
		name   string
		field  unsafe.Pointer
		offset uintptr
	}{
		{"InterfaceLUID", unsafe.Pointer(&row.InterfaceLUID), 8},
		{"InterfaceIndex", unsafe.Pointer(&row.InterfaceIndex), 16},
		{"MaxReassemblySize", unsafe.Pointer(&row.MaxReassemblySize), 20},
		{"InterfaceIdentifier", unsafe.Pointer(&row.InterfaceIdentifier), 24},
		{"MinRouterAdvertisementInterval", unsafe.Pointer(&row.MinRouterAdvertisementInterval), 32},
		{"MaxRouterAdvertisementInterval", unsafe.Pointer(&row.MaxRouterAdvertisementInterval), 36},
		{"AdvertisingEnabled", unsafe.Pointer(&row.AdvertisingEnabled), 40},
		{"ForwardingEnabled", unsafe.Pointer(&row.ForwardingEnabled), 41},
		{"WeakHostSend", unsafe.Pointer(&row.WeakHostSend), 42},
		{"WeakHostReceive", unsafe.Pointer(&row.WeakHostReceive), 43},
		{"UseAutomaticMetric", unsafe.Pointer(&row.UseAutomaticMetric), 44},
		{"UseNeighborUnreachabilityDetection", unsafe.Pointer(&row.UseNeighborUnreachabilityDetection), 45},
		{"ManagedAddressConfigurationSupported", unsafe.Pointer(&row.ManagedAddressConfigurationSupported), 46},
		{"OtherStatefulConfigurationSupported", unsafe.Pointer(&row.OtherStatefulConfigurationSupported), 47},
		{"AdvertiseDefaultRoute", unsafe.Pointer(&row.AdvertiseDefaultRoute), 48},
		{"RouterDiscoveryBehavior", unsafe.Pointer(&row.RouterDiscoveryBehavior), 52},
		{"DadTransmits", unsafe.Pointer(&row.DadTransmits), 56},
		{"BaseReachableTime", unsafe.Pointer(&row.BaseReachableTime), 60},
		{"RetransmitTime", unsafe.Pointer(&row.RetransmitTime), 64},
		{"PathMTUDiscoveryTimeout", unsafe.Pointer(&row.PathMTUDiscoveryTimeout), 68},
		{"LinkLocalAddressBehavior", unsafe.Pointer(&row.LinkLocalAddressBehavior), 72},
		{"LinkLocalAddressTimeout", unsafe.Pointer(&row.LinkLocalAddressTimeout), 76},
		{"ZoneIndices", unsafe.Pointer(&row.ZoneIndices), 80},
		{"SitePrefixLength", unsafe.Pointer(&row.SitePrefixLength), 144},
		{"Metric", unsafe.Pointer(&row.Metric), 148},
		{"NLMTU", unsafe.Pointer(&row.NLMTU), 152},
		{"Connected", unsafe.Pointer(&row.Connected), 156},
		{"SupportsWakeUpPatterns", unsafe.Pointer(&row.SupportsWakeUpPatterns), 157},
		{"SupportsNeighborDiscovery", unsafe.Pointer(&row.SupportsNeighborDiscovery), 158},
		{"SupportsRouterDiscovery", unsafe.Pointer(&row.SupportsRouterDiscovery), 159},
		{"ReachableTime", unsafe.Pointer(&row.ReachableTime), 160},
		{"TransmitOffload", unsafe.Pointer(&row.TransmitOffload), 164},
		{"ReceiveOffload", unsafe.Pointer(&row.ReceiveOffload), 165},
		{"DisableDefaultRoutes", unsafe.Pointer(&row.DisableDefaultRoutes), 166},
	}
	for _, o := range offsets {
		if got := uintptr(o.field) - base; got != o.offset {
			t.Errorf("%s at offset %d, want %d", o.name, got, o.offset)
		}
	}
	if size := unsafe.Sizeof(row); size != mibIPInterfaceRowSize {
		t.Errorf("size %d, want %d", size, mibIPInterfaceRowSize)
	}
}

func TestIPInterfaceRowNotFound(t *testing.T) {
	_, err := getIPInterfaceRow(0xFFFF_FFFF_FFFF_0000, afInet)
	if err == nil {
		t.Fatal("no error for a LUID that does not exist")
	}
	if !errors.Is(err, errIPInterfaceGone) {
		t.Logf("error for a missing LUID is not mapped to gone: %v", err)
	}
}

// TestIPInterfaceRowLive compares what GetIpInterfaceEntry reads through our
// struct with Get-NetIPInterface. It only reads; run it with
// CITRUS_TEST_LIVE_IPINTERFACE=1.
func TestIPInterfaceRowLive(t *testing.T) {
	if os.Getenv("CITRUS_TEST_LIVE_IPINTERFACE") != "1" {
		t.Skip("set CITRUS_TEST_LIVE_IPINTERFACE=1 to compare with Get-NetIPInterface (read-only)")
	}
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-NetIPInterface -PolicyStore ActiveStore | Select-Object ifIndex,AddressFamily,Forwarding,WeakHostSend,NlMtu,InterfaceMetric,InterfaceAlias | ConvertTo-Json -Compress").Output()
	if err != nil {
		t.Fatalf("Get-NetIPInterface: %v", err)
	}
	var rows []struct {
		IfIndex         int    `json:"ifIndex"`
		AddressFamily   int    `json:"AddressFamily"`
		Forwarding      int    `json:"Forwarding"`
		WeakHostSend    int    `json:"WeakHostSend"`
		NlMtu           uint32 `json:"NlMtu"`
		InterfaceMetric uint32 `json:"InterfaceMetric"`
		InterfaceAlias  string `json:"InterfaceAlias"`
	}
	if err = json.Unmarshal(out, &rows); err != nil {
		t.Fatalf("parse Get-NetIPInterface: %v", err)
	}
	checked := 0
	for _, want := range rows {
		luid, err := interfaceIndexToLUID(want.IfIndex)
		if err != nil {
			t.Errorf("%s: LUID: %v", want.InterfaceAlias, err)
			continue
		}
		row, err := getIPInterfaceRow(luid, uint16(want.AddressFamily))
		if err != nil {
			t.Errorf("%s family %d: %v", want.InterfaceAlias, want.AddressFamily, err)
			continue
		}
		name := want.InterfaceAlias + " family " + strconv.Itoa(want.AddressFamily)
		if int(row.InterfaceIndex) != want.IfIndex {
			t.Errorf("%s: index %d, want %d", name, row.InterfaceIndex, want.IfIndex)
		}
		if row.ForwardingEnabled != (want.Forwarding == 1) {
			t.Errorf("%s: Forwarding %v, want %d", name, row.ForwardingEnabled, want.Forwarding)
		}
		if row.WeakHostSend != (want.WeakHostSend == 1) {
			t.Errorf("%s: WeakHostSend %v, want %d", name, row.WeakHostSend, want.WeakHostSend)
		}
		if row.NLMTU != want.NlMtu {
			t.Errorf("%s: NlMtu %d, want %d", name, row.NLMTU, want.NlMtu)
		}
		if row.Metric != want.InterfaceMetric {
			t.Errorf("%s: Metric %d, want %d", name, row.Metric, want.InterfaceMetric)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no interfaces checked")
	}
	t.Logf("checked %d rows", checked)
}
