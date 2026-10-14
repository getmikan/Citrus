package inbound

import (
	"errors"
	"fmt"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/http"
	"github.com/metacubex/mihomo/log"
)

type HTTPOption struct {
	BaseOption
	Users          AuthUsers     `inbound:"users,omitempty"`
	Certificate    string        `inbound:"certificate,omitempty"`
	PrivateKey     string        `inbound:"private-key,omitempty"`
	ClientAuthType string        `inbound:"client-auth-type,omitempty"`
	ClientAuthCert string        `inbound:"client-auth-cert,omitempty"`
	EchKey         string        `inbound:"ech-key,omitempty"`
	RealityConfig  RealityConfig `inbound:"reality-config,omitempty"`
}

func (o HTTPOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type HTTP struct {
	*Base
	authStoreUsers
	config *HTTPOption
	l      []*http.Listener
}

func NewHTTP(options *HTTPOption) (*HTTP, error) {
	base, err := newStreamBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	users, err := newAuthStoreUsers(base.Name(), options.Users)
	if err != nil {
		return nil, err
	}
	return &HTTP{
		Base:           base,
		config:         options,
		authStoreUsers: users,
	}, nil
}

// Config implements constant.InboundListener
func (h *HTTP) Config() C.InboundConfig {
	return h.config
}

// Address implements constant.InboundListener
func (h *HTTP) Address() string {
	var addrList []string
	for _, l := range h.l {
		addrList = append(addrList, l.Address())
	}
	return strings.Join(addrList, ",")
}

// Listen implements constant.InboundListener
func (h *HTTP) Listen(tunnel C.Tunnel) error {
	lc := h.ListenConfig()
	for _, addr := range strings.Split(h.RawAddress(), ",") {
		l, err := http.NewWithConfig(
			LC.AuthServer{
				Enable:         true,
				Listen:         addr,
				AuthStore:      h.authStore(),
				Certificate:    h.config.Certificate,
				PrivateKey:     h.config.PrivateKey,
				ClientAuthType: h.config.ClientAuthType,
				ClientAuthCert: h.config.ClientAuthCert,
				EchKey:         h.config.EchKey,
				RealityConfig:  h.config.RealityConfig.Build(),
			},
			lc,
			tunnel,
			h.Additions()...,
		)
		if err != nil {
			return err
		}
		h.l = append(h.l, l)
	}
	log.Infoln("HTTP[%s] proxy listening at: %s", h.Name(), h.Address())
	return nil
}

// Close implements constant.InboundListener
func (h *HTTP) Close() error {
	var errs []error
	for _, l := range h.l {
		err := l.Close()
		if err != nil {
			errs = append(errs, fmt.Errorf("close tcp listener %s err: %w", l.Address(), err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

var _ C.InboundListener = (*HTTP)(nil)

// SameExceptUsers implements constant.InboundUserUpdater: only between
// configurations that both have users of their own (no users means the
// global authentication, `users: []` turns it off).
func (h *HTTP) SameExceptUsers(config C.InboundConfig) bool {
	other, ok := config.(*HTTPOption)
	return ok && h.store != nil && len(other.Users) > 0 && equalExceptUsers(h.config, other)
}

var _ C.InboundUserUpdater = (*HTTP)(nil)
var _ C.InboundUserLister = (*HTTP)(nil)
