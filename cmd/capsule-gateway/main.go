// Command capsule-gateway is the data plane of the Capsule gateway (docs/gateway/PLAN.md section 4): it accepts
// connections (TLS by SNI, PostgreSQL SSLRequest, SSH over TLS, the capsule/1 tunnel), asks the control plane to
// authorise each one and relays bytes to the destination fixed by the route.
//
// Configuration is by environment (CAPSULE_GW_*, see internal/gateway/data/config.go); a few flags override it.
// The gateway secret is read from CAPSULE_GW_SECRET or CAPSULE_GW_SECRET_FILE only (never from the command line).
//
// Update without cutting connections: start the new binary (it binds the same ports thanks to SO_REUSEPORT), wait until
// its /readyz answers, then send SIGTERM to the old one: it refuses new connections, closes its listeners after a short
// grace period and keeps serving the open ones until they end or CAPSULE_GW_DRAIN_TIMEOUT (24 h) passes.
// A second SIGTERM/SIGINT closes everything at once. SIGHUP reloads the TLS certificates.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kynto/capsule/backend/internal/gateway/data"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() { os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr)) }

func run(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("capsule-gateway", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		showVersion = fs.Bool("version", false, "print the version and exit")
		healthcheck = fs.Bool("healthcheck", false, "probe the local /readyz and exit 0 when ready (for container health checks without a shell)")
		checkConfig = fs.Bool("check-config", false, "validate the configuration and exit")
		listen      = fs.String("listen", "", "listeners \"addr[=kind+kind],...\" (overrides CAPSULE_GW_LISTEN)")
		zone        = fs.String("zone", "", "tunnel zone, tcp.<zone>/udp.<zone> (overrides CAPSULE_GW_ZONE)")
		controlURL  = fs.String("control-url", "", "backend base URL (overrides CAPSULE_GW_CONTROL_URL)")
		metricsAddr = fs.String("metrics-addr", "", "internal address of /metrics, /healthz, /readyz (overrides CAPSULE_GW_METRICS_ADDR; \"off\" disables)")
		routesCache = fs.String("routes-cache", "", "file that keeps the last route table across restarts (overrides CAPSULE_GW_ROUTES_CACHE)")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintf(stdout, "capsule-gateway %s (%s, %s)\n", version, commit, buildDate)
		return 0
	}
	cfg, err := data.ConfigFromEnv(getenv)
	if err != nil {
		fmt.Fprintln(stderr, "capsule-gateway:", err)
		return 2
	}
	if *listen != "" {
		l, err := data.ParseListeners(*listen)
		if err != nil {
			fmt.Fprintln(stderr, "capsule-gateway: -listen:", err)
			return 2
		}
		cfg.Listeners = l
	}
	if *zone != "" {
		cfg.Zone = *zone
	}
	if *controlURL != "" {
		cfg.ControlURL = *controlURL
	}
	if *metricsAddr != "" {
		cfg.MetricsAddr = *metricsAddr
	}
	if *routesCache != "" {
		cfg.RoutesCache = *routesCache
	}
	if *healthcheck {
		return probe(cfg.MetricsAddr, stderr)
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(stderr, "capsule-gateway:", err)
		return 2
	}
	if *checkConfig {
		fmt.Fprintln(stdout, "configuration ok")
		return 0
	}

	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		lvl = slog.LevelInfo
	}
	log := slog.New(slog.NewJSONHandler(stdout, &slog.HandlerOptions{Level: lvl}))
	log.Info("starting", "version", version, "commit", commit, "listeners", len(cfg.Listeners), "zone", cfg.Zone,
		"control_url", cfg.ControlURL, "reuseport", cfg.ReusePort, "tls_pairs", len(cfg.CertFiles), "cgc_keys", len(cfg.CGCKeys))

	ctl, err := data.NewHTTPControl(cfg.ControlURL, cfg.Secret)
	if err != nil {
		log.Error("control plane client", "err", err.Error())
		return 2
	}
	deps := data.Deps{Control: ctl, Logger: log}
	var fc *data.FileCerts
	if len(cfg.CertFiles) > 0 {
		fc, err = data.NewFileCerts(cfg.CertFiles, cfg.KeyFiles)
		if err != nil {
			log.Error("loading TLS certificates", "err", err.Error())
			return 2
		}
		deps.Certs = fc
	} else {
		log.Warn("no TLS certificate configured: terminate-mode routes and the capsule/1 tunnel are disabled")
	}
	srv, err := data.New(cfg, deps)
	if err != nil {
		log.Error("creating the server", "err", err.Error())
		return 2
	}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	if err := srv.Start(ctx); err != nil {
		log.Error("start", "err", err.Error())
		return 1
	}
	if fc != nil {
		go fc.Watch(ctx, time.Minute, func(err error) { log.Error("certificate reload failed; keeping the previous one", "err", err.Error()) })
	}
	var admin *http.Server
	if cfg.MetricsAddr != "" && cfg.MetricsAddr != "off" {
		ln, err := net.Listen("tcp", cfg.MetricsAddr)
		if err != nil {
			log.Error("metrics listener", "err", err.Error())
			srv.Close()
			return 1
		}
		admin = &http.Server{Handler: srv.AdminHandler(), ReadHeaderTimeout: 5 * time.Second}
		go admin.Serve(ln)
		log.Info("admin endpoint", "addr", ln.Addr().String())
	}

	sig := make(chan os.Signal, 4)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	reload := func() {
		if fc == nil {
			return
		}
		if err := fc.Reload(); err != nil {
			log.Error("certificate reload failed; keeping the previous one", "err", err.Error())
			return
		}
		log.Info("certificates reloaded")
	}
	var done chan error // set once draining starts
	for {
		select {
		case s := <-sig:
			if s == syscall.SIGHUP {
				reload()
				continue
			}
			if done != nil { // second signal: stop now
				log.Warn("second signal: closing every connection")
				srv.Close()
				return 1
			}
			log.Info("signal received: draining", "signal", s.String(), "timeout", cfg.DrainTimeout.String())
			dctx, cancel := context.WithTimeout(context.Background(), cfg.DrainTimeout)
			defer cancel()
			done = make(chan error, 1)
			go func() { done <- srv.Drain(dctx, cfg.DrainGrace) }()
		case err := <-done: // nil channel until draining starts
			if admin != nil {
				admin.Close()
			}
			if err != nil {
				log.Warn("drain ended with connections still open", "err", err.Error())
				return 1
			}
			log.Info("stopped")
			return 0
		}
	}
}

// probe asks the local admin endpoint whether the gateway is ready.
func probe(addr string, stderr io.Writer) int {
	if addr == "" || addr == "off" {
		fmt.Fprintln(stderr, "healthcheck: the admin endpoint is disabled")
		return 1
	}
	host := addr
	if strings.HasPrefix(host, ":") {
		host = "127.0.0.1" + host
	}
	c := http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + host + "/readyz")
	if err != nil {
		fmt.Fprintln(stderr, "healthcheck:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(stderr, "healthcheck: not ready:", resp.Status)
		return 1
	}
	return 0
}
