package connaudit

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Finding is one non-routed internal connection. It never holds a secret: Source
// names the variable (env:NAME) or place (file:path:line, runtime) and Endpoint
// is scheme://[***@]host[:port].
type Finding struct {
	ID             string   `json:"id"`
	Severity       Severity `json:"severity"`
	Kind           Kind     `json:"kind"`
	Source         string   `json:"source"`
	Endpoint       string   `json:"endpoint"`
	Recommendation string   `json:"recommendation"`
	Suppressed     bool     `json:"suppressed"`
}

// Recommendations (Spanish, shown as-is in CLI and dashboard) by kind.
var recommendations = map[Kind]string{
	KindDirectPort:   "Conecta por el nombre del gateway (por ejemplo <base>.db.tumi-ai.com) en vez del puerto directo del host: los puertos directos son el método secundario y no pasan por la autorización ni la auditoría del gateway.",
	KindLoopback:     "localhost solo alcanza al propio contenedor. Si apunta a una base o servicio de Capsule, usa su nombre de gateway; si es un proceso propio dentro del contenedor, suprime este aviso con una justificación.",
	KindDockerBridge: "El puente de Docker depende del host y cambia entre despliegues. Usa el nombre de gateway del servicio en lugar de host.docker.internal o una IP 172.16.0.0/12.",
	KindContainer:    "No uses nombres de contenedores de Capsule (capsule-*): son internos, cambian en cada despliegue y saltan la autorización. Usa el nombre de gateway del servicio.",
	KindPrivate:      "Es una dirección de red privada: solo funciona si el contenedor llega a esa red. Si es un servicio de Capsule, usa su nombre de gateway; si es tu propia red, suprime el aviso.",
	KindMetadata:     "El servicio de metadatos de la nube entrega credenciales del host. Una app de cliente no debe consultarlo: elimina esta conexión.",
}

// recommendationUDPDirect is the advice for a UDP destination inside the
// published port range: UDP has no SNI or Host, so the gateway route is the
// capsule:// URI (library or `capsule tunnel`) when the service has it.
const recommendationUDPDirect = "Conectas por UDP directo a un puerto publicado del host: no pasa por la autorización ni la auditoría del gateway. Usa la URI capsule://<proyecto>/<servicio> (librería de Capsule o capsule tunnel) cuando el servicio tenga acceso por gateway; el puerto UDP directo es el método secundario."

func recommendationFor(k Kind, own bool) string {
	if k == KindContainer && own {
		return "Esta app se conecta a su propio contenedor por nombre interno; Capsule lo reemplaza en cada despliegue. Usa el nombre de gateway o localhost dentro del mismo contenedor."
	}
	return recommendations[k]
}

// stableID is stable across line moves and re-deploys: kind + source (without
// line) + sanitised endpoint.
func stableID(kind Kind, srcKey, endpoint string) string {
	sum := sha256.Sum256([]byte(string(kind) + "\x00" + srcKey + "\x00" + endpoint))
	return hex.EncodeToString(sum[:6])
}

// newFinding classifies ep; it returns false for OK destinations.
func newFinding(c *Classifier, ep Endpoint, source string) (Finding, bool) {
	kind, sev := c.Classify(ep.Host, ep.Port)
	if kind == KindOK {
		return Finding{}, false
	}
	srcKey := source
	if strings.HasPrefix(source, "file:") {
		parts := strings.Split(source, ":")
		if len(parts) >= 3 { // file:path:line (the path may hold ':' only on odd names)
			if _, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
				srcKey = strings.Join(parts[:len(parts)-1], ":")
			}
		}
	}
	end := ep.String()
	own := kind == KindContainer && sev == SevWarning
	rec := recommendationFor(kind, own)
	if kind == KindDirectPort && ep.Scheme == "udp" {
		rec = recommendationUDPDirect
	}
	return Finding{
		ID: stableID(kind, srcKey, end), Severity: sev, Kind: kind, Source: source, Endpoint: end,
		Recommendation: rec,
	}, true
}

// AnalyzeEnv inspects the merged variables of a deployment. Values are read in
// memory only; findings carry the variable NAME.
func AnalyzeEnv(env map[string]string, c *Classifier) []Finding {
	if c == nil {
		c = &Classifier{}
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []Finding
	seen := map[string]bool{}
	for _, k := range keys {
		for _, f := range analyzeKV(k, env[k], func(prefix string) int { return portOf(env, prefix) }, "env:"+k, c) {
			if !seen[f.ID] {
				seen[f.ID] = true
				out = append(out, f)
			}
		}
	}
	return out
}

func portOf(env map[string]string, prefix string) int {
	for _, k := range []string{prefix + "_PORT", prefix + "PORT"} {
		for name, v := range env {
			if strings.EqualFold(name, k) {
				if p, err := strconv.Atoi(strings.Trim(strings.TrimSpace(v), `"'`)); err == nil && p > 0 && p < 65536 {
					return p
				}
			}
		}
	}
	return 0
}

// analyzeKV applies the variable rules to one KEY=VALUE pair.
func analyzeKV(key, value string, portFor func(prefix string) int, source string, c *Classifier) []Finding {
	var out []Finding
	add := func(ep Endpoint) {
		if f, ok := newFinding(c, ep, source); ok {
			out = append(out, f)
		}
	}
	for _, ep := range ExtractURLs(value) {
		add(ep)
	}
	if strings.Contains(value, "://") {
		return out
	}
	if prefix, ok := HostKeyPrefix(key); ok {
		if ep, ok := ParseHostPort(value); ok {
			if ep.Port == 0 && portFor != nil {
				ep.Port = portFor(prefix)
			}
			add(ep)
		}
	} else if urlKey(key) {
		if ep, ok := ParseHostPort(value); ok {
			add(ep)
		}
	}
	return out
}

// fileHostRe: "db_host: localhost", "redis.host = 10.0.0.5", "\"mongoHost\": \"capsule-db-x\"".
var fileHostRe = regexp.MustCompile(`(?i)([a-z0-9_.-]*(?:db|database|redis|mongo|mysql|postgres|pg|amqp|rabbit|kafka|cache|queue|broker|sql|memcached|elastic|smtp)[a-z0-9_.-]*?(?:host|hostname|addr|address|server|endpoint))["']?\s*[:=]\s*["']?([^\s"',;#)}\]]+)`)

var hostTail = regexp.MustCompile(`(?i)(host|hostname|addr|address|server|endpoint)$`)

// analyzeLine applies the generic rules to a line of a non-.env file.
func analyzeLine(line, fileContent, source string, c *Classifier) []Finding {
	var out []Finding
	for _, ep := range ExtractURLs(line) {
		if f, ok := newFinding(c, ep, source); ok {
			out = append(out, f)
		}
	}
	for _, m := range fileHostRe.FindAllStringSubmatch(line, -1) {
		ep, ok := ParseHostPort(m[2])
		if !ok {
			continue
		}
		if ep.Port == 0 {
			prefix := hostTail.ReplaceAllString(m[1], "")
			ep.Port = fileNearPort(fileContent, prefix)
		}
		if f, ok := newFinding(c, ep, source); ok {
			out = append(out, f)
		}
	}
	return out
}

// fileNearPort finds "<prefix>port: 5432" anywhere in the file.
func fileNearPort(content, prefix string) int {
	if prefix == "" {
		return 0
	}
	re, err := regexp.Compile(`(?i)` + regexp.QuoteMeta(prefix) + `port["']?\s*[:=]\s*["']?(\d{2,5})`)
	if err != nil {
		return 0
	}
	if m := re.FindStringSubmatch(content); m != nil {
		p, _ := strconv.Atoi(m[1])
		if p > 0 && p < 65536 {
			return p
		}
	}
	return 0
}

// Merge appends extra to base, dropping duplicates by id (base wins).
func Merge(base, extra []Finding) []Finding {
	seen := map[string]bool{}
	for _, f := range base {
		seen[f.ID] = true
	}
	for _, f := range extra {
		if !seen[f.ID] {
			seen[f.ID] = true
			base = append(base, f)
		}
	}
	return base
}

// Sort orders findings: critical first, then warning, then by source.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity.Rank() != fs[j].Severity.Rank() {
			return fs[i].Severity.Rank() > fs[j].Severity.Rank()
		}
		return fs[i].Source < fs[j].Source
	})
}
