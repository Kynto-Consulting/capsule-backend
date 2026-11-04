package data

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
)

// Database protocols by name (G11): Redis and MongoDB with TLS from the first byte are routed by SNI exactly like any
// TLS connection (kind "tls"); MySQL/MariaDB speak first and are served by the "mysql" kind on a dedicated listener
// (proto_mysql.go). What this file adds is what every one of them shares: a per-protocol handler registered with
// Server.RegisterProtocol (it refuses a connection that arrived through the wrong door), a concurrent-connection
// ceiling per protocol and the per-protocol metrics.

// Kinds added by this package (use them in CAPSULE_GW_LISTEN, for example "[::]:3306=mysql").
const (
	KindMySQL      Kind = "mysql"       // server-first MySQL/MariaDB: the gateway greets, TLS (SNI) follows the SSLRequest
	KindRedisPlain Kind = "redis-plain" // clear-text RESP ('*'): refused with a RESP error that asks for TLS
	KindMongoPlain Kind = "mongo-plain" // clear-text MongoDB wire message (OP_MSG/OP_QUERY): refused
)

// Canonical protocol names of the route table (Route.Protocol); aliases map to them.
const (
	protoMySQL = "mysql"
	protoRedis = "redis"
	protoMongo = "mongo"
)

// DefaultProtoMaxConns is the default ceiling of concurrently proxied connections of each database protocol.
const DefaultProtoMaxConns = 1500

// dbState is what the three handlers share. It lives in closures: nothing is added to Server.
type dbState struct {
	s      *Server
	active *prometheus.GaugeVec
	total  *prometheus.CounterVec
	denied *prometheus.CounterVec
	max    map[string]int
	cur    map[string]*atomic.Int64
	once   sync.Once
}

func newDBState(s *Server, reg *prometheus.Registry) *dbState {
	d := &dbState{s: s, max: map[string]int{}, cur: map[string]*atomic.Int64{}}
	d.active = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "gw_proto_conns_active", Help: "Connections being proxied, by database protocol (mysql, redis, mongo)."}, []string{"protocol"})
	d.total = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "gw_proto_conns_total", Help: "Authorised connections of a database protocol, by result."}, []string{"protocol", "result"})
	d.denied = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "gw_proto_denied_total", Help: "Connections of a database protocol refused before routing (wrong door, bad handshake, no TLS)."}, []string{"protocol", "reason"})
	reg.MustRegister(d.active, d.total, d.denied)
	for _, p := range []string{protoMySQL, protoRedis, protoMongo} {
		n := DefaultProtoMaxConns
		if v, ok := s.cfg.ProtoMaxConns[p]; ok {
			n = v
		}
		d.max[p] = n
		d.cur[p] = new(atomic.Int64)
		d.active.WithLabelValues(p).Set(0)
	}
	return d
}

// acquire reserves a slot of the protocol's ceiling (max <= 0 means no ceiling).
func (d *dbState) acquire(p string) bool {
	c := d.cur[p].Add(1)
	if m := d.max[p]; m > 0 && c > int64(m) {
		d.cur[p].Add(-1)
		return false
	}
	return true
}

// dbHandler is the ProtocolHandler of one database protocol.
type dbHandler struct {
	d     *dbState
	name  string
	check func(*Session) string           // "" = right door; otherwise the reason it is refused
	inner func(context.Context, *Session) // proxies the authorised connection
}

// Proxy implements ProtocolHandler.
func (h *dbHandler) Proxy(ctx context.Context, sess *Session) {
	c := sess.Conn
	if why := h.check(sess); why != "" {
		h.d.denied.WithLabelValues(h.name, why).Inc()
		c.Ev.Result = why
		c.Conn.Close()
		return
	}
	if !h.d.acquire(h.name) {
		h.d.denied.WithLabelValues(h.name, "limit_proto").Inc()
		c.Ev.Result = "limit_proto"
		c.Conn.Close()
		return
	}
	defer h.d.cur[h.name].Add(-1)
	g := h.d.active.WithLabelValues(h.name)
	g.Inc()
	defer g.Dec()
	h.inner(ctx, sess)
	res := c.Ev.Result
	if res == "" {
		res = "ok"
	}
	h.d.total.WithLabelValues(h.name, res).Inc()
}

// tlsDirect: the connection started with a TLS record (not behind a PostgreSQL SSLRequest).
func tlsDirect(sess *Session) string {
	if sess.Hello == nil || sess.Conn.PGClassic || sess.Conn.Ev.Kind != KindTLS {
		return "protocol_mismatch"
	}
	return ""
}

// registerDBProtocols installs the G11 kinds and protocol handlers on a Server (called from New).
func (s *Server) registerDBProtocols(reg *prometheus.Registry) {
	d := newDBState(s, reg)
	redis := &dbHandler{d: d, name: protoRedis, check: tlsDirect, inner: s.Proxy}
	mongo := &dbHandler{d: d, name: protoMongo, check: tlsDirect, inner: s.Proxy}
	s.RegisterProtocol("redis", redis)
	s.RegisterProtocol("rediss", redis)
	s.RegisterProtocol("mongo", mongo)
	s.RegisterProtocol("mongodb", mongo)
	my := &dbHandler{d: d, name: protoMySQL, check: func(sess *Session) string {
		if sess.Conn.Ev.Kind != KindMySQL || sess.Hello == nil || len(sess.Raw) < mysqlSSLReqTotal {
			return "protocol_mismatch"
		}
		return ""
	}, inner: s.proxyMySQL}
	s.RegisterProtocol("mysql", my)
	s.RegisterProtocol("mariadb", my)
	s.RegisterKind(redisPlainSniffer{}, KindHandlerFunc(func(ctx context.Context, c *Conn) { s.serveRedisPlain(d, c) }))
	s.RegisterKind(mongoPlainSniffer{}, KindHandlerFunc(func(ctx context.Context, c *Conn) { s.serveMongoPlain(d, c) }))
	s.RegisterKind(mysqlSniffer{}, &mysqlKind{s: s, d: d})
}

// applyProtoEnv reads CAPSULE_GW_PROTO_MAX_CONNS ("mysql=1500,redis=1500,mongo=1500"; 0 = no ceiling).
func applyProtoEnv(c *Config, getenv func(string) string) []string {
	v := getenv("CAPSULE_GW_PROTO_MAX_CONNS")
	if v == "" {
		return nil
	}
	m := map[string]int{}
	for _, item := range strings.Split(v, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		k, n, ok := strings.Cut(item, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		num, err := strconv.Atoi(strings.TrimSpace(n))
		if !ok || err != nil || num < 0 || (k != protoMySQL && k != protoRedis && k != protoMongo) {
			return []string{fmt.Sprintf("CAPSULE_GW_PROTO_MAX_CONNS: bad item %q (want mysql|redis|mongo=N)", item)}
		}
		m[k] = num
	}
	c.ProtoMaxConns = m
	return nil
}
