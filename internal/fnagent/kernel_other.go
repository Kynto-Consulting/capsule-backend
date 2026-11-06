//go:build !linux

package fnagent

import (
	"context"
	"errors"
	"net"
)

// DialContext is only available on Linux (network namespaces).
func (k *KernelTunnel) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return nil, errors.New("network namespaces need Linux")
}
