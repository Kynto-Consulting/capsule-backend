package main

import (
	"log/slog"
	"net/url"

	"github.com/kynto/capsule/backend/internal/config"
	"github.com/kynto/capsule/backend/internal/ingress"
	"github.com/kynto/capsule/backend/internal/server/handlers"
)

// wireIngress resolves the ingress mode (CAPSULE_INGRESS, else ALB_LISTENER_ARN empty => caddy),
// registers the "ingress" entry of GET /platform/capabilities and returns the config for the router.
func wireIngress(cfg *config.Config, logger *slog.Logger) ingress.Config {
	ic := ingress.Resolve(cfg.Ingress, cfg.ALBListenerARN, cfg.IngressHost, cfg.IngressIPv4, cfg.IngressIPv6)
	ic.AppsDomain = cfg.AppsDomain
	for _, raw := range []string{cfg.FrontendURL, cfg.OIDCIssuer} {
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			ic.OwnHosts = append(ic.OwnHosts, u.Hostname())
		}
	}
	handlers.RegisterCapability("ingress", func() any {
		return map[string]any{"mode": string(ic.Mode), "host": ic.Host, "ipv4": ic.IPv4, "ipv6": ic.IPv6}
	})
	logger.Info("ingress", "mode", ic.Mode, "host", ic.Host, "ipv4", ic.IPv4, "ipv6", ic.IPv6)
	if ic.Caddy() && ic.Host == "" && ic.IPv4 == "" && ic.IPv6 == "" {
		logger.Warn("ingress without ALB but no CAPSULE_INGRESS_HOST / CAPSULE_INGRESS_IPV4 / CAPSULE_INGRESS_IPV6: custom domains cannot be verified")
	}
	return ic
}
