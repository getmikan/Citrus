package common

import (
	"fmt"
	"strings"

	C "github.com/metacubex/mihomo/constant"
)

type InUser struct {
	Base
	// users is a set: the list of a rule can be long (the users a panel moved
	// to a restricted mode), and it is checked for every connection.
	users   map[string]struct{}
	adapter string
	payload string
}

func (u *InUser) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	if _, ok := u.users[metadata.InUser]; ok {
		return true, u.adapter
	}
	return false, ""
}

func (u *InUser) RuleType() C.RuleType {
	return C.InUser
}

func (u *InUser) Adapter() string {
	return u.adapter
}

func (u *InUser) Payload() string {
	return u.payload
}

func NewInUser(iUsers, adapter string) (*InUser, error) {
	list := strings.Split(iUsers, "/")
	users := make(map[string]struct{}, len(list))
	for _, user := range list {
		user = strings.TrimSpace(user)
		if len(user) == 0 {
			return nil, fmt.Errorf("in user couldn't be empty")
		}
		users[user] = struct{}{}
	}

	return &InUser{
		Base:    Base{},
		users:   users,
		adapter: adapter,
		payload: iUsers,
	}, nil
}

var _ C.Rule = (*InUser)(nil)
