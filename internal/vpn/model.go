// Package vpn is the Capsule VPN Connector: tunnel definitions, validation, provider configuration renderers,
// secret redaction and the audit vocabulary (docs/vpn-connector.md). Tunnels are opened by the gateway
// (package vpn/gateway) on the work node, never by the backend.
package vpn

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Providers.
const (
	ProviderWireGuard = "wireguard"
	ProviderFortiGate = "fortigate"
	ProviderIPsec     = "ipsec"
	ProviderOpenVPN   = "openvpn"
)

// Providers lists the supported providers.
var Providers = []string{ProviderWireGuard, ProviderFortiGate, ProviderIPsec, ProviderOpenVPN}

// Status values of a tunnel as reported by the gateway.
const (
	StatusDown       = "down"
	StatusConnecting = "connecting"
	StatusUp         = "up"
	StatusError      = "error"
	StatusDisabled   = "disabled"
)

// Audit event kinds.
const (
	EventCreated      = "created"
	EventUpdated      = "updated"
	EventDeleted      = "deleted"
	EventEnabled      = "enabled"
	EventDisabled     = "disabled" // kill switch
	EventConnecting   = "connecting"
	EventUp           = "up"
	EventDown         = "down"
	EventReconnect    = "reconnect"
	EventRunStarted   = "run_started"
	EventRunFinished  = "run_finished"
	EventDeniedTarget = "denied_target"
)

// Defaults and ceilings that keep one tunnel from saturating the customer's VPN.
const (
	DefaultMaxConns  = 4
	MaxMaxConns      = 64
	DefaultBandwidth = 8 << 20 // bytes per second
)

var nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$`)
var pinRe = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// Tunnel is the stored definition. The secret is never part of its JSON.
type Tunnel struct {
	ID              uuid.UUID       `json:"id"`
	OrgID           uuid.UUID       `json:"org_id"`
	ProjectID       uuid.UUID       `json:"project_id"`
	Name            string          `json:"name"`
	Provider        string          `json:"provider"`
	Host            string          `json:"host"`
	CIDRs           []string        `json:"cidrs"`
	CertPin         string          `json:"cert_pin,omitempty"`
	Config          json.RawMessage `json:"config,omitempty"`
	SecretEnc       []byte          `json:"-"`
	HasSecret       bool            `json:"has_secret"`
	Enabled         bool            `json:"enabled"`
	MaxConns        int             `json:"max_conns"`
	BandwidthBps    int64           `json:"bandwidth_bps"`
	Status          string          `json:"status"`
	LastHandshakeAt *time.Time      `json:"last_handshake_at,omitempty"`
	LastError       string          `json:"last_error,omitempty"`
	CreatedBy       *uuid.UUID      `json:"created_by,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

// Event is one audit row.
type Event struct {
	ID        int64     `json:"id"`
	TunnelID  uuid.UUID `json:"tunnel_id"`
	ProjectID uuid.UUID `json:"project_id"`
	At        time.Time `json:"at"`
	Kind      string    `json:"kind"`
	Message   string    `json:"message"`
	Actor     string    `json:"actor"`
}

// Spec is the user input of `capsule vpn create`.
type Spec struct {
	Name         string          `json:"name"`
	Provider     string          `json:"provider"`
	Host         string          `json:"host"`
	CIDRs        []string        `json:"cidrs"`
	CertPin      string          `json:"cert_pin"`
	Config       json.RawMessage `json:"config"`
	Secret       string          `json:"secret"` // JSON document that depends on the provider; never stored in clear
	MaxConns     int             `json:"max_conns"`
	BandwidthBps int64           `json:"bandwidth_bps"`
}

// ErrInvalid wraps every validation failure (HTTP 422).
var ErrInvalid = errors.New("invalid vpn spec")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Normalize validates a Spec and fills defaults. It returns the cleaned copy.
func (s Spec) Normalize() (Spec, error) {
	s.Name = strings.ToLower(strings.TrimSpace(s.Name))
	if !nameRe.MatchString(s.Name) {
		return s, invalid("name must be 1-40 chars of a-z, 0-9 and '-'")
	}
	s.Provider = strings.ToLower(strings.TrimSpace(s.Provider))
	ok := false
	for _, p := range Providers {
		ok = ok || p == s.Provider
	}
	if !ok {
		return s, invalid("provider must be one of %s", strings.Join(Providers, ", "))
	}
	s.Host = strings.TrimSpace(s.Host)
	if _, _, err := net.SplitHostPort(s.Host); err != nil {
		return s, invalid("host must be host:port")
	}
	if len(s.CIDRs) == 0 {
		return s, invalid("at least one --cidr is required (only declared networks are routed)")
	}
	norm := make([]string, 0, len(s.CIDRs))
	for _, c := range s.CIDRs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			return s, invalid("bad cidr %q", c)
		}
		if p.Bits() == 0 {
			return s, invalid("cidr %s would route everything; declare the customer network", c)
		}
		norm = append(norm, p.Masked().String())
	}
	s.CIDRs = norm
	s.CertPin = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s.CertPin)), "sha256:")
	if s.CertPin != "" && !pinRe.MatchString(s.CertPin) {
		return s, invalid("cert-pin must be the SHA-256 of the remote certificate (64 hex chars)")
	}
	if s.MaxConns <= 0 {
		s.MaxConns = DefaultMaxConns
	}
	if s.MaxConns > MaxMaxConns {
		return s, invalid("max_conns above %d", MaxMaxConns)
	}
	if s.BandwidthBps <= 0 {
		s.BandwidthBps = DefaultBandwidth
	}
	if strings.TrimSpace(s.Secret) == "" {
		return s, invalid("credentials are required (use --secret-stdin)")
	}
	if err := validateSecret(s.Provider, s.Secret); err != nil {
		return s, err
	}
	return s, nil
}

// WGSecret is the secret document of a WireGuard tunnel.
type WGSecret struct {
	PrivateKey    string `json:"private_key"`
	PeerPublicKey string `json:"peer_public_key"`
	PresharedKey  string `json:"preshared_key,omitempty"`
	Address       string `json:"address"` // our address inside the tunnel, e.g. 10.99.0.2/32
	Keepalive     int    `json:"keepalive,omitempty"`
}

// UserPassSecret is the secret of fortigate/openvpn.
type UserPassSecret struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// IPsecSecret is the secret of an IPsec tunnel (PSK or user/pass for IKEv2 EAP).
type IPsecSecret struct {
	PSK      string `json:"psk,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	LocalID  string `json:"local_id,omitempty"`
}

func validateSecret(provider, secret string) error {
	switch provider {
	case ProviderWireGuard:
		var w WGSecret
		if err := json.Unmarshal([]byte(secret), &w); err != nil {
			return invalid("wireguard secret must be JSON {private_key, peer_public_key, address}")
		}
		if err := checkKey(w.PrivateKey, "private_key"); err != nil {
			return err
		}
		if err := checkKey(w.PeerPublicKey, "peer_public_key"); err != nil {
			return err
		}
		if w.PresharedKey != "" {
			if err := checkKey(w.PresharedKey, "preshared_key"); err != nil {
				return err
			}
		}
		if _, err := netip.ParsePrefix(w.Address); err != nil {
			return invalid("wireguard address must be a CIDR like 10.99.0.2/32")
		}
	case ProviderFortiGate, ProviderOpenVPN:
		var u UserPassSecret
		if err := json.Unmarshal([]byte(secret), &u); err != nil || u.Username == "" || u.Password == "" {
			return invalid("%s secret must be JSON {username, password}", provider)
		}
	case ProviderIPsec:
		var s IPsecSecret
		if err := json.Unmarshal([]byte(secret), &s); err != nil || (s.PSK == "" && (s.Username == "" || s.Password == "")) {
			return invalid("ipsec secret must be JSON {psk} or {username, password}")
		}
	}
	return nil
}

func checkKey(k, field string) error {
	if len(k) != 44 || !strings.HasSuffix(k, "=") {
		return invalid("%s must be a base64 WireGuard key (44 chars)", field)
	}
	return nil
}

// Redactor masks known secret values in log text.
type Redactor struct{ secrets []string }

// NewRedactor builds a redactor from literal values (values under 4 chars are ignored to avoid mangling logs).
func NewRedactor(values ...string) *Redactor {
	r := &Redactor{}
	r.Add(values...)
	return r
}

// Add registers more values.
func (r *Redactor) Add(values ...string) {
	for _, v := range values {
		if len(v) >= 4 {
			r.secrets = append(r.secrets, v)
		}
	}
}

// AddJSONValues registers every string value found in a JSON document (used with the tunnel secret).
func (r *Redactor) AddJSONValues(doc string) {
	var m map[string]any
	if json.Unmarshal([]byte(doc), &m) != nil {
		return
	}
	for _, v := range m {
		if s, ok := v.(string); ok {
			r.Add(s)
		}
	}
}

// Mask replaces every registered value in s by ***.
func (r *Redactor) Mask(s string) string {
	for _, v := range r.secrets {
		s = strings.ReplaceAll(s, v, "***")
	}
	return s
}

func splitHost(hp string) (string, string) {
	h, p, err := net.SplitHostPort(hp)
	if err != nil {
		return hp, ""
	}
	return h, p
}

func cidrNetmask(c string) (string, string) {
	p, err := netip.ParsePrefix(c)
	if err != nil {
		return c, ""
	}
	return p.Masked().Addr().String(), net.IP(net.CIDRMask(p.Bits(), 32)).String()
}
