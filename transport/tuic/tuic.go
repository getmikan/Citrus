package tuic

import (
	"fmt"

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/mihomo/transport/tuic/common"
	"github.com/metacubex/mihomo/transport/tuic/types"
	v5 "github.com/metacubex/mihomo/transport/tuic/v5"
)

type ClientOptionV5 = v5.ClientOption

type Client = types.Client

func NewClientV5(clientOption *ClientOptionV5, udp bool, dialFn DialFunc) Client {
	return v5.NewClient(clientOption, udp, dialFn)
}

type DialFunc = types.DialFunc

var TooManyOpenStreams = types.TooManyOpenStreams

var ClientClosed = types.ClientClosed

// ErrV4Unsupported is returned for configs that still set the TUIC v4 `token`.
var ErrV4Unsupported = fmt.Errorf("%w: TUIC v4 is no longer supported, use uuid/password (v5)", C.ErrRemovedProtocol)

const DefaultStreamReceiveWindow = common.DefaultStreamReceiveWindow
const DefaultConnectionReceiveWindow = common.DefaultConnectionReceiveWindow

var PacketOverHeadV5 = v5.PacketOverHead
var MaxFragSizeV5 = v5.MaxFragSize

type UdpRelayMode = types.UdpRelayMode

const (
	QUIC   = types.QUIC
	NATIVE = types.NATIVE
)
