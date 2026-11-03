package handlers

import (
	"net/http"
	"sort"
	"sync"
)

// CapabilityProvider contributes one entry to GET /platform/capabilities.
type CapabilityProvider interface {
	// Name is the top-level key ("backups", "git", "ports", "oidc", ...).
	Name() string
	// Capability returns the JSON-serializable value for that key.
	Capability() any
}

type capabilityFunc struct {
	name string
	fn   func() any
}

func (c capabilityFunc) Name() string    { return c.name }
func (c capabilityFunc) Capability() any { return c.fn() }

var (
	capsMu   sync.RWMutex
	capsProv = map[string]CapabilityProvider{}
)

// RegisterCapability registers (or replaces) the provider of a capability. When
// both the default and the registered value are JSON objects (map[string]any),
// they are merged with the registered keys winning; otherwise the registered
// value replaces the default. Safe to call from any package at startup.
func RegisterCapability(name string, fn func() any) {
	RegisterCapabilityProvider(capabilityFunc{name: name, fn: fn})
}

// RegisterCapabilityProvider is RegisterCapability for a CapabilityProvider.
func RegisterCapabilityProvider(p CapabilityProvider) {
	capsMu.Lock()
	capsProv[p.Name()] = p
	capsMu.Unlock()
}

// capabilityDefaults is what the endpoint answers while nobody registered a part.
func capabilityDefaults() map[string]any {
	return map[string]any{
		"backups": map[string]any{"enabled": false, "default_schedule": "daily"},
		"git":     map[string]any{"enabled": false, "url": "", "ssh_host": ""},
		"ports":   map[string]any{"enabled": false, "range": "41000-41999", "host": ""},
		"oidc":    map[string]any{"enabled": false, "issuer": ""},
	}
}

// Capabilities builds the response body.
func Capabilities() map[string]any {
	out := capabilityDefaults()
	capsMu.RLock()
	names := make([]string, 0, len(capsProv))
	for n := range capsProv {
		names = append(names, n)
	}
	sort.Strings(names)
	provs := make([]CapabilityProvider, 0, len(names))
	for _, n := range names {
		provs = append(provs, capsProv[n])
	}
	capsMu.RUnlock()
	for _, p := range provs {
		v := p.Capability()
		if v == nil {
			continue
		}
		if dm, ok := out[p.Name()].(map[string]any); ok {
			if vm, ok := v.(map[string]any); ok {
				for k, x := range vm {
					dm[k] = x
				}
				continue
			}
		}
		out[p.Name()] = v
	}
	return out
}

// PlatformCapabilities handles GET /api/v1/platform/capabilities (any authenticated user).
func PlatformCapabilities(w http.ResponseWriter, _ *http.Request) {
	respondJSON(w, http.StatusOK, Capabilities())
}
