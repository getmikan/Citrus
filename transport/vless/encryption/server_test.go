package encryption

import (
	"net"
	"testing"
	"time"
)

func newTicketStore(secondsFrom, secondsTo int64) *ServerInstance {
	return &ServerInstance{
		SecondsFrom: secondsFrom,
		SecondsTo:   secondsTo,
		Lasts:       make(map[int64][16]byte),
		Tickets:     make([][16]byte, 0, 4),
		Sessions:    make(map[[16]byte]*ServerSession),
	}
}

func testTicket(n int) (t [16]byte) {
	t[0], t[1], t[15] = 1, byte(n>>8), byte(n)
	return
}

func checkTicketStore(t *testing.T, i *ServerInstance) {
	t.Helper()
	if len(i.Tickets) != len(i.Sessions) {
		t.Fatalf("tickets %d != sessions %d", len(i.Tickets), len(i.Sessions))
	}
	for _, ticket := range i.Tickets {
		if i.Sessions[ticket] == nil {
			t.Fatalf("ticket %x queued without a session", ticket)
		}
	}
}

func setMaxServerSessions(t *testing.T, n int) {
	old := MaxServerSessions
	MaxServerSessions = n
	t.Cleanup(func() { MaxServerSessions = old })
}

func TestServerTicketStoreCapEvictsOldest(t *testing.T) {
	setMaxServerSessions(t, 3)
	i := newTicketStore(600, 0)
	now := time.Unix(1_700_000_000, 0)
	for n := 0; n < 10; n++ {
		i.storeTicketLocked(now, testTicket(n), &ServerSession{})
		checkTicketStore(t, i)
		if len(i.Sessions) > 3 {
			t.Fatalf("store grew to %d past the cap", len(i.Sessions))
		}
	}
	for n := 0; n < 7; n++ {
		if i.Sessions[testTicket(n)] != nil {
			t.Fatalf("ticket %d should have been evicted", n)
		}
	}
	for n := 7; n < 10; n++ {
		if i.Sessions[testTicket(n)] == nil {
			t.Fatalf("ticket %d should be kept", n)
		}
	}
}

func TestServerTicketStoreExpiry(t *testing.T) {
	setMaxServerSessions(t, 100)
	i := newTicketStore(60, 0)
	t0 := time.Unix(1_700_000_000, 0)
	for n := 0; n < 5; n++ {
		i.storeTicketLocked(t0, testTicket(n), &ServerSession{})
	}
	t1 := t0.Add(2 * time.Minute)
	for n := 5; n < 8; n++ {
		i.storeTicketLocked(t1, testTicket(n), &ServerSession{})
	}
	// The first batch expires at minute (t0+60)/60+2.
	i.expireTicketsLocked(time.Unix((t0.Unix()+60)/60*60+120, 0))
	checkTicketStore(t, i)
	if len(i.Sessions) != 3 || i.Sessions[testTicket(5)] == nil {
		t.Fatalf("expected only the second batch, got %d sessions", len(i.Sessions))
	}
	i.expireTicketsLocked(time.Unix((t1.Unix()+60)/60*60+120, 0))
	checkTicketStore(t, i)
	if len(i.Sessions) != 0 {
		t.Fatalf("expected an empty store, got %d sessions", len(i.Sessions))
	}
}

// An expiry mark whose ticket was already evicted by the cap must not wipe the
// newer tickets that are still valid.
func TestServerTicketStoreExpiryAfterEviction(t *testing.T) {
	setMaxServerSessions(t, 2)
	i := newTicketStore(60, 0)
	t0 := time.Unix(1_700_000_000, 0)
	i.storeTicketLocked(t0, testTicket(0), &ServerSession{})
	t1 := t0.Add(5 * time.Minute)
	i.storeTicketLocked(t1, testTicket(1), &ServerSession{})
	i.storeTicketLocked(t1, testTicket(2), &ServerSession{}) // evicts ticket 0
	if i.Sessions[testTicket(0)] != nil {
		t.Fatal("ticket 0 should have been evicted")
	}
	i.expireTicketsLocked(time.Unix((t0.Unix()+60)/60*60+120, 0))
	checkTicketStore(t, i)
	if len(i.Sessions) != 2 {
		t.Fatalf("newer tickets were dropped: %d left", len(i.Sessions))
	}
}

func TestServerTicketStoreDuplicate(t *testing.T) {
	setMaxServerSessions(t, 4)
	i := newTicketStore(600, 0)
	now := time.Unix(1_700_000_000, 0)
	i.storeTicketLocked(now, testTicket(1), &ServerSession{})
	s := &ServerSession{}
	i.storeTicketLocked(now, testTicket(1), s)
	checkTicketStore(t, i)
	if len(i.Tickets) != 1 || i.Sessions[testTicket(1)] != s {
		t.Fatal("a duplicate ticket must replace the session without queueing twice")
	}
}

// Full 1-RTT handshakes stay within the cap.
func TestServerHandshakeTicketCap(t *testing.T) {
	setMaxServerSessions(t, 3)
	priv, password, _, err := GenX25519("")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer("mlkem768x25519plus.native.600s." + priv)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := NewClient("mlkem768x25519plus.native.1rtt." + password)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			s, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer s.Close()
				_, _ = server.Handshake(s, nil)
			}()
		}
	}()
	for n := 0; n < 6; n++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.Handshake(c) // the ticket is stored before the server hello is sent
		c.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	server.RWLock.RLock()
	defer server.RWLock.RUnlock()
	checkTicketStore(t, server)
	if len(server.Sessions) != 3 {
		t.Fatalf("expected 3 stored sessions, got %d", len(server.Sessions))
	}
}
