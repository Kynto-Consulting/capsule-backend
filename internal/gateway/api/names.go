package api

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gateway/store"
)

var nonLabel = regexp.MustCompile(`[^a-z0-9]+`)

// slugLabel turns free text into a DNS label fragment (same rule as migration 000060): lowercase, runs of
// anything else become one hyphen, trimmed, at most max characters. "" when nothing is left.
func slugLabel(s string, max int) string {
	s = strings.Trim(nonLabel.ReplaceAllString(strings.ToLower(s), "-"), "-")
	if len(s) > max {
		s = strings.Trim(s[:max], "-")
	}
	return s
}

// uniqueName returns base, or base+suffix when base is taken, always a valid service name.
func uniqueName(base, suffix string, used map[string]bool) string {
	name := base
	if used[name] {
		if len(base)+len(suffix) > 63 {
			base = strings.Trim(base[:63-len(suffix)], "-")
		}
		name = base + suffix
	}
	for i := 2; used[name]; i++ {
		sf := suffix + "-" + strconv.Itoa(i)
		b := base
		if len(b)+len(sf) > 63 {
			b = strings.Trim(b[:63-len(sf)], "-")
		}
		name = b + sf
	}
	used[name] = true
	return name
}

// dbProtocol maps a database engine to the gateway protocol (same rule as migration 000060).
func dbProtocol(engine string) string {
	e := strings.ToLower(engine)
	switch {
	case strings.HasPrefix(e, "postgres"), strings.Contains(e, "aurora-postgres"):
		return "postgres"
	case strings.HasPrefix(e, "mysql"), strings.HasPrefix(e, "maria"):
		return "mysql"
	case strings.HasPrefix(e, "redis"):
		return "redis"
	case strings.HasPrefix(e, "mongo"):
		return "mongo"
	}
	return "tcp"
}

// isDBProtocol reports whether names of the protocol live under *.db (PLAN 3.1).
func isDBProtocol(p string) bool {
	switch p {
	case "postgres", "mysql", "redis", "mongo":
		return true
	}
	return false
}

// serviceHost is the SNI/Host of a service: "<service>-<project slug>.db.<zone>" for databases and
// "<service>-<project slug>.apps.<zone>" for everything else. The label must fit in 63 characters.
func (s *Service) serviceHost(svc *store.Service, p *domain.Project) (string, error) {
	sub := "apps"
	if isDBProtocol(svc.Protocol) {
		sub = "db"
	}
	return s.hostFor(svc.Name, p.Slug, sub)
}

// appsHost is the *.apps hostname of a service (random-port fallback and tcp/udp).
func (s *Service) appsHost(svc *store.Service, p *domain.Project) (string, error) {
	return s.hostFor(svc.Name, p.Slug, "apps")
}

func (s *Service) hostFor(name, slug, sub string) (string, error) {
	label := name + "-" + slug
	if slug == "" || len(label) > 63 {
		return "", errBadRequest("service name plus project slug exceed 63 characters: use a shorter service name")
	}
	if !store.ValidServiceName(label) {
		return "", errBadRequest("service name or project slug cannot form a DNS name")
	}
	return fmt.Sprintf("%s.%s.%s", label, sub, s.cfg.Zone), nil
}

// shortID is the 12-hex identifier of a project in container names ("capsule-app-<short>").
func shortID(id uuid.UUID) string { return strings.ReplaceAll(id.String(), "-", "")[:12] }

// destFor decides the internal destination of a service's route; the client never chooses it. A service that mirrors
// a published port or database is reached on that host port (the data plane runs on the docker host); a service
// created through the API is reached on its project container by name on capsule-net.
func (s *Service) destFor(svc *store.Service) (host string, port int, err error) {
	for _, a := range svc.Accesses {
		if a.Kind == store.AccessDirectPort && a.Port != nil && *a.Port > 0 {
			return s.cfg.DestHost, *a.Port, nil
		}
	}
	if svc.ProjectID != uuid.Nil && svc.ContainerPort > 0 && svc.ProjectPortID == nil && svc.DatabaseID == nil {
		return "capsule-app-" + shortID(svc.ProjectID), svc.ContainerPort, nil
	}
	return "", 0, errBadRequest("cannot determine the destination of this service yet")
}

func transportOf(protocol string) string {
	if protocol == "udp" {
		return store.TransportUDP
	}
	return store.TransportTCP
}

func itoa(n int) string { return strconv.Itoa(n) }
