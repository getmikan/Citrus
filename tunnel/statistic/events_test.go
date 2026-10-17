package statistic

import (
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/eventbus"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func nextEvent(t *testing.T, s *eventbus.Subscription) eventbus.Event {
	t.Helper()
	select {
	case e := <-s.C():
		return e
	case <-time.After(2 * time.Second):
		t.Fatal("no event")
		return eventbus.Event{}
	}
}

func TestLimitEvents(t *testing.T) {
	mask, err := eventbus.ParseTypes(eventbus.TypeUserLimit)
	require.NoError(t, err)
	sub := eventbus.Subscribe(mask, 64)
	defer sub.Close()

	um, clock := newTestUserManager()
	um.SetCloser(func(UserKey, func() bool) {})
	require.NoError(t, um.SetLimit(UserLimit{Inbound: "in", User: "alice", Quota: 1000, MaxConns: 1}))

	c, err := um.Admit(keyA, ip1)
	require.NoError(t, err)

	// max-conns: a rejection, reported once a second per user
	_, err = um.Admit(keyA, ip2)
	require.Error(t, err)
	_, err = um.Admit(keyA, ip2)
	require.Error(t, err)
	e := nextEvent(t, sub)
	assert.Equal(t, eventbus.TypeUserLimit, e.Type)
	assert.Equal(t, eventbus.UserLimit{Inbound: "in", User: "alice", Reason: RejectMaxConns, Action: eventbus.LimitRejected, Detail: "max-conns 1 reached", Remote: ip2.String()}, e.Data)
	clock.advance(2 * time.Second)
	_, err = um.Admit(keyA, ip2)
	require.Error(t, err)
	assert.Equal(t, int64(1), nextEvent(t, sub).Data.(eventbus.UserLimit).Suppressed)

	// the quota is used up: the user's connections are closed
	c.limit.Load().addUp(1500, nil)
	assert.Equal(t, eventbus.UserLimit{Inbound: "in", User: "alice", Reason: RejectQuota, Action: eventbus.LimitClosed, Detail: "quota of 1000 bytes used up"}, nextEvent(t, sub).Data)

	// a user that is already expired when its limit applies
	require.NoError(t, um.SetLimit(UserLimit{Inbound: "in", User: "bob", ExpireAt: clock.now().Unix() - 1}))
	d := nextEvent(t, sub).Data.(eventbus.UserLimit)
	assert.Equal(t, "bob", d.User)
	assert.Equal(t, RejectExpired, d.Reason)
	assert.Equal(t, eventbus.LimitClosed, d.Action)
}

func TestAuthSuccessEvents(t *testing.T) {
	mask, err := eventbus.ParseTypes(eventbus.TypeAuth)
	require.NoError(t, err)
	sub := eventbus.Subscribe(mask, 64)
	defer sub.Close()
	window := eventbus.AuthWindow
	eventbus.AuthWindow = 20 * time.Millisecond
	defer func() { eventbus.AuthWindow = window }()

	um, _ := newTestUserManager()
	c1 := um.Acquire(keyA, ip1)
	e := nextEvent(t, sub).Data.(eventbus.Auth)
	assert.Equal(t, eventbus.Auth{Result: eventbus.AuthSuccess, Inbound: "in", User: "alice", Remote: ip1.String(), Count: 1}, e)

	// more connections from an online address are not new logins
	c2 := um.Acquire(keyA, ip1)
	um.Release(c2, ip1)
	um.Release(c1, ip1)
	um.Acquire(keyA, ip1) // still online within IPRelease
	um.Acquire(keyB, ip1) // another user
	assert.Equal(t, "bob", nextEvent(t, sub).Data.(eventbus.Auth).User)
	select {
	case e := <-sub.C():
		t.Fatalf("alice was reported again: %+v", e) // a repetition at the end of the window
	case <-time.After(100 * time.Millisecond):
	}
}
