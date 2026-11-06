// Package fnagent is the work node: it only makes outbound calls to the Capsule API (claim, sync, finish), keeps the
// tunnel gateways of the runs it receives and executes each function in a limited container (docs/vpn-connector.md).
package fnagent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/fn"
)

// Client talks to /api/v1/fn/agent/* with the node token.
type Client struct {
	Base  string // https://api.example
	Token string // capnode_...
	HTTP  *http.Client
}

func (c *Client) do(ctx context.Context, path string, in, out any) (int, error) {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(c.Base, "/")+"/api/v1/fn/agent"+path, body)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return resp.StatusCode, nil
	}
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return resp.StatusCode, fmt.Errorf("%s: %d %s", path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if out != nil {
		return resp.StatusCode, json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode, nil
}

// Claim returns the next assignment or nil.
func (c *Client) Claim(ctx context.Context) (*fn.Assignment, error) {
	var a fn.Assignment
	code, err := c.do(ctx, "/claim", struct{}{}, &a)
	if err != nil || code == http.StatusNoContent {
		return nil, err
	}
	return &a, nil
}

// Sync reports live runs/tunnels and learns what to stop.
func (c *Client) Sync(ctx context.Context, running, tunnels []uuid.UUID) (fn.SyncReply, error) {
	var rep fn.SyncReply
	_, err := c.do(ctx, "/sync", map[string]any{"running": running, "tunnels": tunnels}, &rep)
	return rep, err
}

// FinishReport is the end of a run.
type FinishReport struct {
	Status   string `json:"status"`
	ExitCode *int   `json:"exit_code,omitempty"`
	BytesIn  int64  `json:"bytes_in"`
	BytesOut int64  `json:"bytes_out"`
	LogTail  string `json:"log_tail"`
}

// Finish reports the end of a run.
func (c *Client) Finish(ctx context.Context, run uuid.UUID, r FinishReport) error {
	_, err := c.do(ctx, "/runs/"+run.String()+"/finish", r, nil)
	return err
}

// TunnelStatus reports the health of a tunnel.
func (c *Client) TunnelStatus(ctx context.Context, id uuid.UUID, status string, handshake time.Time, lastErr string) error {
	body := map[string]any{"status": status, "error": lastErr}
	if !handshake.IsZero() {
		body["last_handshake_unix"] = handshake.Unix()
	}
	_, err := c.do(ctx, "/tunnels/"+id.String()+"/status", body, nil)
	return err
}
