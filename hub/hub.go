package hub

import (
	"github.com/metacubex/mihomo/component/eventbus"
	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/hub/route"
	"github.com/metacubex/mihomo/log"
)

type Option func(*config.Config)

func WithExternalUI(externalUI string) Option {
	return func(cfg *config.Config) {
		cfg.Controller.ExternalUI = externalUI
	}
}

func WithExternalController(externalController string) Option {
	return func(cfg *config.Config) {
		cfg.Controller.ExternalController = externalController
	}
}

func WithExternalControllerTLS(externalControllerTLS string) Option {
	return func(cfg *config.Config) {
		cfg.Controller.ExternalControllerTLS = externalControllerTLS
	}
}

func WithExternalControllerUnix(externalControllerUnix string) Option {
	return func(cfg *config.Config) {
		cfg.Controller.ExternalControllerUnix = externalControllerUnix
	}
}

func WithExternalControllerPipe(externalControllerPipe string) Option {
	return func(cfg *config.Config) {
		cfg.Controller.ExternalControllerPipe = externalControllerPipe
	}
}

func WithExternalControllerRoutingMark(externalControllerRoutingMark int) Option {
	return func(cfg *config.Config) {
		cfg.Controller.ExternalControllerRoutingMark = externalControllerRoutingMark
	}
}

// WithExternalControllerAllowInsecure sets external-controller-allow-insecure.
func WithExternalControllerAllowInsecure(allow bool) Option {
	return func(cfg *config.Config) {
		cfg.Controller.AllowInsecure = allow
	}
}

// WithExternalControllerAllowLegacyWebSocketToken enables the compatibility
// path that sends the main controller secret in WebSocket URLs.
func WithExternalControllerAllowLegacyWebSocketToken(allow bool) Option {
	return func(cfg *config.Config) { cfg.Controller.AllowLegacyWebSocketToken = allow }
}

func WithSecret(secret string) Option {
	return func(cfg *config.Config) {
		cfg.Controller.Secret = secret
	}
}

// ApplyConfig dispatch configure to all parts include ExternalController
func ApplyConfig(cfg *config.Config) {
	applyRoute(cfg)
	executor.ApplyConfig(cfg, true)
}

func applyRoute(cfg *config.Config) {
	if cfg.Controller.ExternalUI != "" {
		route.SetUIPath(cfg.Controller.ExternalUI)
	}
	route.ReCreateServer(routeConfig(cfg))
}

func routeConfig(cfg *config.Config) *route.Config {
	return &route.Config{
		Addr:           cfg.Controller.ExternalController,
		TLSAddr:        cfg.Controller.ExternalControllerTLS,
		UnixAddr:       cfg.Controller.ExternalControllerUnix,
		PipeAddr:       cfg.Controller.ExternalControllerPipe,
		RoutingMark:    cfg.Controller.ExternalControllerRoutingMark,
		Secret:         cfg.Controller.Secret,
		Certificate:    cfg.TLS.Certificate,
		PrivateKey:     cfg.TLS.PrivateKey,
		ClientAuthType: cfg.TLS.ClientAuthType,
		ClientAuthCert: cfg.TLS.ClientAuthCert,
		EchKey:         cfg.TLS.EchKey,
		DohServer:      cfg.Controller.ExternalDohServer,
		IsDebug:        cfg.General.LogLevel == log.DEBUG,
		Cors: route.Cors{
			AllowOrigins:        cfg.Controller.Cors.AllowOrigins,
			AllowPrivateNetwork: cfg.Controller.Cors.AllowPrivateNetwork,
		},
		AllowInsecure:             cfg.Controller.AllowInsecure,
		AllowLegacyWebSocketToken: cfg.Controller.AllowLegacyWebSocketToken,
	}
}

// controllerReloader lets PUT /configs apply the controller part of a new
// configuration, with the same command line overrides as the startup and
// SIGHUP: without them a reload would drop, say, a secret given by -secret.
func controllerReloader(options []Option) route.ControllerReloader {
	return func(cfg *config.Config) (func(), error) {
		for _, option := range options {
			option(cfg)
		}
		rc := routeConfig(cfg)
		if err := rc.Validate(); err != nil {
			return nil, err
		}
		return func() { applyRoute(cfg) }, nil
	}
}

// Parse call at the beginning of mihomo
func Parse(configBytes []byte, options ...Option) error {
	var cfg *config.Config
	var err error

	if len(configBytes) != 0 {
		cfg, err = executor.ParseWithBytes(configBytes)
	} else {
		cfg, err = executor.Parse()
	}

	if err != nil {
		eventbus.PublishConfigReload(err)
		return err
	}

	for _, option := range options {
		option(cfg)
	}

	route.SetControllerReloader(controllerReloader(options))
	ApplyConfig(cfg)
	return nil
}
