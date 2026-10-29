package xhttp

import (
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUploadQueueMaxPackets(t *testing.T) {
	q := NewUploadQueue(2)
	ch := make(chan struct{})
	go func() {
		err := q.Push(Packet{Seq: 0, Payload: []byte{'0'}})
		assert.NoError(t, err)
		err = q.Push(Packet{Seq: 1, Payload: []byte{'1'}})
		assert.NoError(t, err)
		err = q.Push(Packet{Seq: 2, Payload: []byte{'2'}})
		assert.NoError(t, err)
		err = q.Push(Packet{Seq: 4, Payload: []byte{'4'}})
		assert.NoError(t, err)
		err = q.Push(Packet{Seq: 5, Payload: []byte{'5'}})
		assert.NoError(t, err)
		err = q.Push(Packet{Seq: 6, Payload: []byte{'6'}})
		assert.NoError(t, err)
		err = q.Push(Packet{Seq: 7, Payload: []byte{'7'}})
		assert.ErrorIs(t, err, io.ErrClosedPipe)
		close(ch)
	}()

	buf := make([]byte, 20)
	n, err := q.Read(buf)
	assert.Equal(t, 1, n)
	assert.Equal(t, []byte{'0'}, buf[:n])
	assert.NoError(t, err)

	n, err = q.Read(buf)
	assert.Equal(t, 1, n)
	assert.Equal(t, []byte{'1'}, buf[:n])

	n, err = q.Read(buf)
	assert.Equal(t, 1, n)
	assert.Equal(t, []byte{'2'}, buf[:n])

	n, err = q.Read(buf)
	assert.Equal(t, 0, n)
	assert.ErrorIs(t, err, ErrQueueTooLarge)

	err = q.Close()
	assert.NoError(t, err)

	<-ch
}

func TestUploadQueueRelease(t *testing.T) {
	q := NewUploadQueue(4)
	var released []uint64
	push := func(seq uint64, payload string) {
		err := q.Push(Packet{Seq: seq, Payload: []byte(payload), Release: func() { released = append(released, seq) }})
		assert.NoError(t, err)
	}
	push(1, "") // an empty packet is released as soon as it is popped
	push(0, "abcd")
	push(2, "ef")

	buf := make([]byte, 3)
	n, err := q.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, "abc", string(buf[:n]))
	assert.Empty(t, released, "released before the payload was read out")

	n, err = q.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, "d", string(buf[:n]))
	assert.Equal(t, []uint64{0}, released)

	n, err = q.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, "ef", string(buf[:n]))
	assert.Equal(t, []uint64{0, 1, 2}, released)

	assert.NoError(t, q.Close())
}

func TestUploadQueueDropsConsumedSeq(t *testing.T) {
	q := NewUploadQueue(1)
	buf := make([]byte, 4)
	for seq := uint64(0); seq < 2; seq++ {
		assert.NoError(t, q.Push(Packet{Seq: seq, Payload: []byte{byte('0' + seq)}}))
		n, err := q.Read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 1, n)
	}

	// Replayed seqs must neither count against maxPackets nor block Push.
	released := 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 4; i++ {
			assert.NoError(t, q.Push(Packet{Seq: uint64(i % 2), Payload: []byte{'x'}, Release: func() { released++ }}))
		}
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Push blocked on consumed seqs")
	}
	assert.Equal(t, 4, released)

	assert.NoError(t, q.Push(Packet{Seq: 2, Payload: []byte{'2'}}))
	n, err := q.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, "2", string(buf[:n]))
	assert.NoError(t, q.Close())
}
