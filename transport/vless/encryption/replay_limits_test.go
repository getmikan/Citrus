package encryption

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func replayKey(n int) (k [32]byte) {
	binary.BigEndian.PutUint64(k[:], uint64(n))
	return
}

func setReplayLimits(t *testing.T, perTicket, perServer int) {
	t.Helper()
	oldTicket, oldServer := MaxSessionReplayKeys, MaxServerReplayKeys
	MaxSessionReplayKeys, MaxServerReplayKeys = perTicket, perServer
	t.Cleanup(func() { MaxSessionReplayKeys, MaxServerReplayKeys = oldTicket, oldServer })
}

func TestReplayTicketRetiredAtLimit(t *testing.T) {
	setReplayLimits(t, 3, 10)
	i := newTicketStore(600, 0)
	ticket := testTicket(1)
	s := &ServerSession{}
	i.storeTicketLocked(time.Now(), ticket, s)
	for n := 0; n < 3; n++ {
		if got, replay := i.useTicket(ticket, replayKey(n)); got != s || replay {
			t.Fatal("valid resumption rejected")
		}
	}
	if got, replay := i.useTicket(ticket, replayKey(0)); got != nil || !replay {
		t.Fatal("replayed key was accepted at capacity")
	}
	if got, replay := i.useTicket(ticket, replayKey(3)); got != nil || replay {
		t.Fatal("full ticket did not request a new handshake")
	}
	if i.replayKeys != 0 || s.replayKeys != 0 {
		t.Fatal("retired ticket retained its replay budget")
	}
	// Clearing the map is safe only because this ticket stays unusable.
	if got, _ := i.useTicket(ticket, replayKey(0)); got != nil {
		t.Fatal("old key was accepted after ticket retirement")
	}
	s.NfsKeys.Range(func(_, _ any) bool { t.Error("retired ticket retained a key"); return false })
}

func TestReplayServerBudgetAcrossTickets(t *testing.T) {
	setReplayLimits(t, 10, 3)
	i := newTicketStore(600, 0)
	for n := 0; n < 4; n++ {
		ticket := testTicket(n)
		i.storeTicketLocked(time.Now(), ticket, &ServerSession{})
		s, replay := i.useTicket(ticket, replayKey(n))
		if replay || (s != nil) != (n < 3) {
			t.Fatalf("unexpected admission for ticket %d", n)
		}
	}
	if i.replayKeys != 3 {
		t.Fatalf("global replay budget = %d", i.replayKeys)
	}
	// Evicting a ticket releases its keys for other tickets.
	i.deleteTicketLocked(testTicket(0))
	ticket := testTicket(4)
	i.storeTicketLocked(time.Now(), ticket, &ServerSession{})
	if s, _ := i.useTicket(ticket, replayKey(4)); s == nil {
		t.Fatal("released budget was not reusable")
	}
}

func TestReplayConcurrentDuplicate(t *testing.T) {
	i := newTicketStore(600, 0)
	ticket := testTicket(1)
	i.storeTicketLocked(time.Now(), ticket, &ServerSession{})
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for n := 0; n < 64; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s, _ := i.useTicket(ticket, replayKey(1)); s != nil {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 || i.replayKeys != 1 {
		t.Fatal("concurrent duplicate consumed more than one admission")
	}
}

func TestReplayBudgetReleasedOnExpiryAndReplacement(t *testing.T) {
	for _, replace := range []bool{false, true} {
		i := newTicketStore(60, 0)
		ticket := testTicket(1)
		now := time.Unix(1_700_000_000, 0)
		i.storeTicketLocked(now, ticket, &ServerSession{})
		i.useTicket(ticket, replayKey(1))
		if replace {
			i.storeTicketLocked(now, ticket, &ServerSession{})
		} else {
			i.expireTicketsLocked(time.Unix((now.Unix()+60)/60*60+120, 0))
		}
		if i.replayKeys != 0 {
			t.Fatal("ticket cleanup leaked replay budget")
		}
	}
}

func TestReplayLimitForcesFreshHandshake(t *testing.T) {
	setReplayLimits(t, 2, 8)
	priv, public, _, err := GenX25519("")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer("mlkem768x25519plus.native.600s." + priv)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := NewClient("mlkem768x25519plus.native.0rtt." + public)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var handlers sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				secure, err := server.Handshake(conn, nil)
				if err == nil {
					_, _ = io.Copy(secure, secure)
				}
			}()
		}
	}()
	defer func() { ln.Close(); <-done; handlers.Wait() }()
	for n := 0; n < 5; n++ {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		secure, err := client.Handshake(conn)
		if err == nil {
			_, err = secure.Write([]byte("echo"))
			if err == nil {
				var got [4]byte
				_, err = io.ReadFull(secure, got[:])
				if err == nil && string(got[:]) != "echo" {
					t.Fatal("corrupted echo")
				}
			}
		}
		conn.Close()
		// Initial 1-RTT, two accepted resumptions, expired-ticket response,
		// and a fresh successful 1-RTT using the same client configuration.
		if n == 3 {
			if !errors.Is(err, ErrNewHandshakeNeeded) {
				t.Fatalf("expected expired ticket, got %v", err)
			}
		} else if err != nil {
			t.Fatalf("connection %d: %v", n, err)
		}
	}
}
