// Command capsule-fn-agent is the work node of Capsule functions (docs/vpn-connector.md).
// It only makes outbound HTTPS calls to the Capsule API and runs function containers with limits and, when attached,
// a tunnel gateway. It never listens for incoming connections.
//
//	CAPSULE_API_URL   https://api.example        (required)
//	CAPSULE_NODE_TOKEN capnode_...               (required; `capsule fn node create <name>` prints it once)
//	CAPSULE_FN_SOCKS_ROOT  /run/capsule/fn       (default)
//	CAPSULE_FN_PARALLEL    2                     (runs at the same time on this node)
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/kynto/capsule/backend/internal/fnagent"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	base, tok := os.Getenv("CAPSULE_API_URL"), os.Getenv("CAPSULE_NODE_TOKEN")
	if base == "" || tok == "" {
		log.Error("CAPSULE_API_URL and CAPSULE_NODE_TOKEN are required")
		os.Exit(2)
	}
	root := os.Getenv("CAPSULE_FN_SOCKS_ROOT")
	if root == "" {
		root = "/run/capsule/fn"
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		log.Error("socks root", "error", err)
		os.Exit(1)
	}
	par, _ := strconv.Atoi(os.Getenv("CAPSULE_FN_PARALLEL"))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	mgr := fnagent.NewManager()
	ag := &fnagent.Agent{Client: &fnagent.Client{Base: base, Token: tok}, Runner: fnagent.DockerRunner{}, Mgr: mgr, SocksRoot: root, MaxParallel: par, Log: log}
	log.Info("capsule-fn-agent started", "api", base)
	ag.Loop(ctx)
	for _, id := range mgr.IDs() {
		mgr.Stop(id)
	}
}
