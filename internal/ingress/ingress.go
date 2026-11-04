// Package ingress describes how HTTP(S) traffic reaches Capsule and verifies
// that a custom domain points at it.
//
// Two modes exist:
//
//   - "alb": the legacy AWS Application Load Balancer. Custom domains get an ACM
//     certificate and host rules on the ALB listener (handlers/domain_ssl.go).
//   - "caddy": no load balancer. Caddy terminates TLS on the server and issues
//     certificates on demand, asking GET /internal/tls/ask before each issuance.
//     Capsule only verifies that the domain's DNS points at the server.
//
// Mode selection (Resolve): CAPSULE_INGRESS=alb|caddy wins when set; otherwise
// the mode is "alb" when ALB_LISTENER_ARN is set and "caddy" when it is empty.
package ingress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
)

// Mode is the ingress mode.
type Mode string

const (
	ModeALB   Mode = "alb"
	ModeCaddy Mode = "caddy"
)

// Domain verification states stored in domains.status for the caddy mode.
const (
	StatusPendingDNS = "pending_dns"
	StatusActive     = "active"
	StatusFailed     = "failed"
)

// Config is the resolved ingress configuration.
type Config struct {
	Mode Mode
	// Host is the ingress name the owner creates (CAPSULE_INGRESS_HOST), e.g.
	// ingress.apps.example.com: customers point a CNAME at it.
	Host string
	// IPv4/IPv6 are the public addresses of the server (CAPSULE_INGRESS_IPV4 /
	// CAPSULE_INGRESS_IPV6): customers point A/AAAA records at them.
	IPv4 string
	IPv6 string
	// OwnHosts are Capsule's own public names (app, api, apps, ingress host).
	// They are never custom domains and are always accepted by /internal/tls/ask.
	OwnHosts []string
	// AppsDomain is the wildcard base (apps.example.com): no custom domain may live under it.
	AppsDomain string
}

// Resolve computes the mode and normalises the values.
func Resolve(explicit, albListenerARN, host, ipv4, ipv6 string) Config {
	c := Config{
		Host: normHost(host),
		IPv4: strings.TrimSpace(ipv4),
		IPv6: strings.TrimSpace(ipv6),
	}
	switch strings.ToLower(strings.TrimSpace(explicit)) {
	case "caddy":
		c.Mode = ModeCaddy
	case "alb":
		c.Mode = ModeALB
	default:
		if strings.TrimSpace(albListenerARN) == "" {
			c.Mode = ModeCaddy
		} else {
			c.Mode = ModeALB
		}
	}
	return c
}

// Caddy reports whether the no-ALB mode is active.
func (c Config) Caddy() bool { return c.Mode == ModeCaddy }

// Record is a DNS record the customer must create.
type Record struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Records returns the records for a domain: a CNAME to the ingress host when
// configured, otherwise A/AAAA to the server addresses. Empty when nothing is configured.
func (c Config) Records(domainName string) []Record {
	if c.Host != "" {
		return []Record{{Type: "CNAME", Name: domainName, Value: c.Host}}
	}
	var out []Record
	if c.IPv4 != "" {
		out = append(out, Record{Type: "A", Name: domainName, Value: c.IPv4})
	}
	if c.IPv6 != "" {
		out = append(out, Record{Type: "AAAA", Name: domainName, Value: c.IPv6})
	}
	return out
}

// Instructions is the Spanish text shown next to the records.
func (c Config) Instructions(domainName string) string {
	recs := c.Records(domainName)
	if len(recs) == 0 {
		return "El servidor aún no tiene configurado el destino DNS (CAPSULE_INGRESS_HOST o CAPSULE_INGRESS_IPV4/IPV6); contacta al administrador."
	}
	parts := make([]string, len(recs))
	for i, r := range recs {
		parts[i] = fmt.Sprintf("%s %s → %s", r.Type, r.Name, r.Value)
	}
	return "Crea en tu DNS: " + strings.Join(parts, " y ") + ". El certificado HTTPS se emite automáticamente la primera vez que se visita el dominio."
}

// Reserved reports whether a hostname may not be registered as a custom domain
// (Capsule's own names and anything under the apps wildcard).
func (c Config) Reserved(host string) bool {
	host = normHost(host)
	for _, o := range c.OwnHosts {
		if host == normHost(o) {
			return true
		}
	}
	if c.Host != "" && host == c.Host {
		return true
	}
	if a := normHost(c.AppsDomain); a != "" && (host == a || strings.HasSuffix(host, "."+a)) {
		return true
	}
	return false
}

// OwnSet returns the lower-cased set of Capsule's own names.
func (c Config) OwnSet() map[string]bool {
	m := map[string]bool{}
	for _, o := range c.OwnHosts {
		if h := normHost(o); h != "" {
			m[h] = true
		}
	}
	if h := normHost(c.AppsDomain); h != "" {
		m[h] = true
	}
	if c.Host != "" {
		m[c.Host] = true
	}
	return m
}

func normHost(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// NormalizeDomain lowercases and validates a custom domain name (letters, digits,
// hyphens, at least two labels, no wildcard, no IP literal, no port).
func NormalizeDomain(s string) (string, error) {
	h := normHost(s)
	if h == "" {
		return "", errors.New("el dominio es obligatorio")
	}
	if len(h) > 253 {
		return "", errors.New("el dominio es demasiado largo")
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return "", errors.New("indica un nombre de dominio, no una dirección IP")
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return "", errors.New("el dominio debe tener al menos dos partes, por ejemplo midominio.com")
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", errors.New("el dominio tiene un formato inválido")
		}
		for _, ch := range l {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return "", errors.New("el dominio solo puede contener letras, números y guiones (sin comodines ni puertos)")
			}
		}
	}
	return h, nil
}

// Resolver is the subset of net.Resolver used for verification (fakeable in tests).
type Resolver interface {
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Result is the outcome of a verification.
type Result struct {
	Status  string // StatusPendingDNS | StatusActive | StatusFailed
	Message string // Spanish, shown to the user
}

const okMessage = "El dominio apunta al servidor. El certificado HTTPS se emite en la primera visita."

// Verify checks that domainName points at this server. It is read-only and never
// contacts AWS. A name that does not resolve yet is pending_dns (DNS propagation);
// one that resolves elsewhere is failed.
func Verify(ctx context.Context, r Resolver, c Config, domainName string) Result {
	if len(c.Records(domainName)) == 0 {
		return Result{StatusFailed, "El servidor no tiene configurado el destino DNS; contacta al administrador."}
	}
	// 1. CNAME to the ingress host.
	if c.Host != "" {
		if cn, err := r.LookupCNAME(ctx, domainName); err == nil && normHost(cn) == c.Host {
			return Result{StatusActive, okMessage}
		}
	}
	// 2. Addresses: every resolved address must be one of ours.
	want, err := c.targetAddrs(ctx, r)
	if err != nil {
		return Result{StatusPendingDNS, "No se pudo resolver el destino del servidor (" + c.Host + "); inténtalo de nuevo en unos minutos."}
	}
	got, err := r.LookupIPAddr(ctx, domainName)
	if err != nil || len(got) == 0 {
		var dnsErr *net.DNSError
		if err == nil || (errors.As(err, &dnsErr) && dnsErr.IsNotFound) {
			return Result{StatusPendingDNS, "El dominio todavía no resuelve. Crea el registro DNS indicado; la propagación puede tardar hasta unas horas."}
		}
		return Result{StatusPendingDNS, "No se pudo consultar el DNS del dominio; inténtalo de nuevo en unos minutos."}
	}
	var foreign []string
	for _, a := range got {
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			continue
		}
		if !want[ip.Unmap()] {
			foreign = append(foreign, ip.Unmap().String())
		}
	}
	if len(foreign) == 0 {
		return Result{StatusActive, okMessage}
	}
	sort.Strings(foreign)
	return Result{StatusFailed, "El dominio apunta a otro destino (" + strings.Join(foreign, ", ") + "). Corrige el registro DNS y vuelve a verificar."}
}

// targetAddrs returns the server addresses: the configured IPs, plus the
// addresses the ingress host resolves to.
func (c Config) targetAddrs(ctx context.Context, r Resolver) (map[netip.Addr]bool, error) {
	m := map[netip.Addr]bool{}
	for _, s := range []string{c.IPv4, c.IPv6} {
		if s == "" {
			continue
		}
		if ip, err := netip.ParseAddr(s); err == nil {
			m[ip.Unmap()] = true
		}
	}
	if c.Host != "" {
		addrs, err := r.LookupIPAddr(ctx, c.Host)
		if err != nil && len(m) == 0 {
			return nil, err
		}
		for _, a := range addrs {
			if ip, ok := netip.AddrFromSlice(a.IP); ok {
				m[ip.Unmap()] = true
			}
		}
	}
	if len(m) == 0 {
		return nil, errors.New("no target addresses")
	}
	return m, nil
}
