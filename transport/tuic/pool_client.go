package tuic

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"

	list "github.com/bahlo/generic-list-go"
)

type PoolClient struct {
	newClientOptionV5 *ClientOptionV5

	dialFn          DialFunc
	tcpClients      list.List[Client]
	tcpClientsMutex sync.Mutex
	udpClients      list.List[Client]
	udpClientsMutex sync.Mutex

	// closed stops the pool from handing out or creating clients once the
	// proxy is removed, so nothing reopens a QUIC connection after Close
	closed atomic.Bool
}

func (t *PoolClient) DialContext(ctx context.Context, metadata *C.Metadata) (net.Conn, error) {
	client, err := t.getClient(false)
	if err != nil {
		return nil, err
	}
	conn, err := client.DialContext(ctx, metadata)
	if errors.Is(err, TooManyOpenStreams) {
		if client, err = t.newClient(false); err != nil {
			return nil, err
		}
		conn, err = client.DialContext(ctx, metadata)
	}
	if err != nil {
		return nil, err
	}
	return N.NewRefConn(conn, t), err
}

func (t *PoolClient) ListenPacket(ctx context.Context, metadata *C.Metadata) (net.PacketConn, error) {
	client, err := t.getClient(true)
	if err != nil {
		return nil, err
	}
	pc, err := client.ListenPacket(ctx, metadata)
	if errors.Is(err, TooManyOpenStreams) {
		if client, err = t.newClient(true); err != nil {
			return nil, err
		}
		pc, err = client.ListenPacket(ctx, metadata)
	}
	if err != nil {
		return nil, err
	}
	return N.NewRefPacketConn(pc, t), nil
}

func (t *PoolClient) newClient(udp bool) (Client, error) {
	clients := &t.tcpClients
	clientsMutex := &t.tcpClientsMutex
	if udp {
		clients = &t.udpClients
		clientsMutex = &t.udpClientsMutex
	}

	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	// checked under the lock, so a client pushed here is either seen by Close or never made
	if t.closed.Load() {
		return nil, ClientClosed
	}

	client := NewClientV5(t.newClientOptionV5, udp, t.dialFn)

	client.SetLastVisited(time.Now())

	clients.PushFront(client)
	return client, nil
}

func (t *PoolClient) getClient(udp bool) (Client, error) {
	clients := &t.tcpClients
	clientsMutex := &t.tcpClientsMutex
	if udp {
		clients = &t.udpClients
		clientsMutex = &t.udpClientsMutex
	}
	var bestClient Client

	err := func() error {
		clientsMutex.Lock()
		defer clientsMutex.Unlock()
		if t.closed.Load() {
			return ClientClosed
		}
		for it := clients.Front(); it != nil; {
			client := it.Value
			if client == nil {
				next := it.Next()
				clients.Remove(it)
				it = next
				continue
			}
			if bestClient == nil {
				bestClient = client
			} else {
				if client.OpenStreams() < bestClient.OpenStreams() {
					bestClient = client
				}
			}
			it = it.Next()
		}
		for it := clients.Front(); it != nil; {
			client := it.Value
			if client != bestClient && client.OpenStreams() == 0 && time.Now().Sub(client.LastVisited()) > 30*time.Minute {
				client.Close()
				next := it.Next()
				clients.Remove(it)
				it = next
				continue
			}
			it = it.Next()
		}
		return nil
	}()
	if err != nil {
		return nil, err
	}

	if bestClient == nil {
		return t.newClient(udp)
	} else {
		bestClient.SetLastVisited(time.Now())
		return bestClient, nil
	}
}

// Close closes every pooled client and stops the pool from making new ones.
// Clients with streams still open finish them before their QUIC connection is
// closed; without this the connections were only released by a GC finalizer.
// Close is safe to call more than once.
func (t *PoolClient) Close() error {
	t.closed.Store(true)
	closeClients := func(clients *list.List[Client], clientsMutex *sync.Mutex) {
		clientsMutex.Lock()
		defer clientsMutex.Unlock()
		for it := clients.Front(); it != nil; it = it.Next() {
			if client := it.Value; client != nil {
				client.Close()
			}
		}
		clients.Init()
	}
	closeClients(&t.tcpClients, &t.tcpClientsMutex)
	closeClients(&t.udpClients, &t.udpClientsMutex)
	return nil
}

func NewPoolClientV5(clientOption *ClientOptionV5, dialFn DialFunc) *PoolClient {
	p := &PoolClient{
		dialFn: dialFn,
	}
	newClientOption := *clientOption
	p.newClientOptionV5 = &newClientOption
	return p
}
