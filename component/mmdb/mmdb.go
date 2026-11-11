package mmdb

import (
	"net"
	"sync"

	mihomoOnce "github.com/metacubex/mihomo/common/once"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/oschwald/maxminddb-golang"
)

type databaseType = uint8

const (
	typeMaxmind databaseType = iota
	typeSing
	typeMetaV0
)

var (
	ipReader  IPReader
	asnReader ASNReader
	ipOnce    sync.Once
	asnOnce   sync.Once

	// ipMu and asnMu guard the readers' lifetime. Loading and lookups hold
	// them shared; ReplaceIP and ReplaceASN hold them exclusively, so a
	// reader is never closed (its memory-mapped file unmapped) under a
	// lookup in flight.
	ipMu  sync.RWMutex
	asnMu sync.RWMutex
)

func LoadFromBytes(buffer []byte) {
	ipMu.RLock()
	defer ipMu.RUnlock()
	ipOnce.Do(func() {
		mmdb, err := maxminddb.FromBytes(buffer)
		if err != nil {
			log.Fatalln("Can't load mmdb: %s", err.Error())
		}
		ipReader = IPReader{Reader: mmdb}
		switch mmdb.Metadata.DatabaseType {
		case "sing-geoip":
			ipReader.databaseType = typeSing
		case "Meta-geoip0":
			ipReader.databaseType = typeMetaV0
		default:
			ipReader.databaseType = typeMaxmind
		}
	})
}

func Verify(path string) bool {
	instance, err := maxminddb.Open(path)
	if err == nil {
		instance.Close()
	}
	return err == nil
}

func IPInstance() IPReader {
	ipMu.RLock()
	defer ipMu.RUnlock()
	return ipInstance()
}

// LookupCode looks ip up in the current MMDB. Loading and the lookup share
// one critical section, so a lookup that races ReplaceIP waits for the new
// database instead of reading the closed one and reporting no match.
func LookupCode(ip net.IP) []string {
	ipMu.RLock()
	defer ipMu.RUnlock()
	return ipInstance().lookupCode(ip)
}

// ipInstance loads the MMDB once; the caller holds ipMu shared.
func ipInstance() IPReader {
	ipOnce.Do(func() {
		mmdbPath := C.Path.MMDB()
		log.Infoln("Load MMDB file: %s", mmdbPath)
		mmdb, err := maxminddb.Open(mmdbPath)
		if err != nil {
			log.Fatalln("Can't load MMDB: %s", err.Error())
		}
		ipReader = IPReader{Reader: mmdb}
		switch mmdb.Metadata.DatabaseType {
		case "sing-geoip":
			ipReader.databaseType = typeSing
		case "Meta-geoip0":
			ipReader.databaseType = typeMetaV0
		default:
			ipReader.databaseType = typeMaxmind
		}
	})

	return ipReader
}

func ASNInstance() ASNReader {
	asnMu.RLock()
	defer asnMu.RUnlock()
	return asnInstance()
}

// LookupASN is LookupCode for the ASN database.
func LookupASN(ip net.IP) (string, string) {
	asnMu.RLock()
	defer asnMu.RUnlock()
	return asnInstance().lookupASN(ip)
}

// asnInstance loads the ASN database once; the caller holds asnMu shared.
func asnInstance() ASNReader {
	asnOnce.Do(func() {
		ASNPath := C.Path.ASN()
		log.Infoln("Load ASN file: %s", ASNPath)
		asn, err := maxminddb.Open(ASNPath)
		if err != nil {
			log.Fatalln("Can't load ASN: %s", err.Error())
		}
		asnReader = ASNReader{Reader: asn}
	})

	return asnReader
}

func ReloadIP() {
	ipMu.Lock()
	defer ipMu.Unlock()
	mihomoOnce.Reset(&ipOnce)
}

func ReloadASN() {
	asnMu.Lock()
	defer asnMu.Unlock()
	mihomoOnce.Reset(&asnOnce)
}

// ReplaceIP closes the loaded MMDB reader, runs write to replace the file
// (a memory-mapped file cannot be replaced on Windows while it is mapped),
// and has the next IPInstance load the file again. Lookups wait until it
// returns rather than reading an unmapped buffer.
func ReplaceIP(write func() error) error {
	ipMu.Lock()
	defer ipMu.Unlock()
	if mihomoOnce.Done(&ipOnce) && ipReader.Reader != nil {
		_ = ipReader.Reader.Close()
	}
	defer mihomoOnce.Reset(&ipOnce)
	return write()
}

// ReplaceASN is ReplaceIP for the ASN database.
func ReplaceASN(write func() error) error {
	asnMu.Lock()
	defer asnMu.Unlock()
	if mihomoOnce.Done(&asnOnce) && asnReader.Reader != nil {
		_ = asnReader.Reader.Close()
	}
	defer mihomoOnce.Reset(&asnOnce)
	return write()
}
