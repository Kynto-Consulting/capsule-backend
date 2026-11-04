// Package catalog is the versioned catalog of atomic permissions ("resource:action") of the
// Capsule permission engine (docs/permissions/SPEC.md section 3).
//
// The catalog lives in code, never in the database. It is published as catalog.json (generated
// from this file; a test fails when the file is stale) so the UI and the CLI keep no copy.
//
// Rules this package enforces:
//
//   - 99 entries: 26 organization-only, 66 project/repo/environment (assignment:read and
//     assignment:grant are one entry each, valid at organization scope too) and 7 platform.
//   - The bit of a permission in a Set is its position in the table below. The table is
//     APPEND-ONLY: entries are never renamed, reordered, reused or removed (they are marked
//     Deprecated). The hex masks that /me/permissions will publish depend on it.
//   - A permission unknown to this build is ignored by Set parsing (it grants nothing).
//
// catalog does not import the authz package (Expand is generic over string-kinded types) so
// authz and the engine can import catalog without an import cycle.
package catalog

import (
	"sort"
	"strings"
)

// Version is the catalog version. It grows when permissions are appended.
const Version = 1

// Scope says where a permission can be granted.
type Scope string

const (
	ScopeOrg      Scope = "org"
	ScopeProject  Scope = "project"
	ScopeRepo     Scope = "repo"
	ScopeEnv      Scope = "env"
	ScopePlatform Scope = "platform"
)

// Label holds the user-visible texts of a permission.
type Label struct {
	ES string `json:"es"`
	EN string `json:"en"`
}

// Perm is one catalog entry.
type Perm struct {
	ID         string   `json:"id"`
	Bit        int      `json:"bit"`        // position in Set; stable forever
	Scopes     []Scope  `json:"scopes"`     // where it may be granted
	Sensitive  bool     `json:"sensitive"`  // strict verification path and denial audit (SPEC 12.2)
	Tokenable  bool     `json:"tokenable"`  // may be carried by an API token (SPEC 9.1)
	LegacyGap  bool     `json:"legacy_gap"` // kept for equivalence with today's behaviour (SPEC G7/G8)
	Requires   []string `json:"requires"`   // dependencies validated when saving a template (SPEC 3.4)
	Legacy     []string `json:"legacy"`     // old authz actions this permission derives from
	Since      int      `json:"since"`      // catalog version that introduced it
	Deprecated bool     `json:"deprecated"` // kept but not offered
	Group      string   `json:"group"`      // UI grouping
	Label      Label    `json:"label"`
}

// HasScope reports whether the permission may be granted at scope s.
func (p Perm) HasScope(s Scope) bool {
	for _, x := range p.Scopes {
		if x == s {
			return true
		}
	}
	return false
}

// raw is the source table. Flags: s sensitive, g legacy_gap. Scopes: O org, P project, R repo, E env, L platform.
type raw struct {
	id, scopes, flags string
	legacy            string // old actions separated by spaces
	es, en            string
}

// The order is the bit order. APPEND ONLY.
var table = []raw{
	// ---- organization (SPEC 3.1), 26 entries; assignment:* are further below ----
	{"org:read", "O", "", "", "Ver la organización", "View the organization"},
	{"org:update", "O", "", "", "Renombrar la organización", "Rename the organization"},
	{"org:delete", "O", "s", "", "Borrar la organización", "Delete the organization"},
	{"org:access-policy", "O", "s", "", "Cambiar el modo de acceso a proyectos", "Change the project access policy"},
	{"org:transfer", "O", "s", "", "Transferir la propiedad", "Transfer ownership"},
	{"member:read", "O", "", "", "Ver miembros", "View members"},
	{"member:invite", "O", "", "", "Invitar miembros", "Invite members"},
	{"member:update", "O", "", "", "Cambiar el rol de un miembro", "Change a member role"},
	{"member:remove", "O", "", "", "Quitar miembros", "Remove members"},
	{"member:leave", "O", "", "", "Salir de la organización", "Leave the organization"},
	{"member:suspend", "O", "", "", "Suspender miembros en la organización", "Suspend members in the organization"},
	{"group:read", "O", "", "", "Ver grupos", "View groups"},
	{"group:manage", "O", "s", "", "Gestionar grupos y su membresía", "Manage groups and their membership"},
	{"template:read", "O", "", "", "Ver plantillas de roles", "View role templates"},
	{"template:manage", "O", "s", "", "Gestionar plantillas personalizadas", "Manage custom templates"},
	{"audit:read", "O", "", "", "Ver la auditoría", "View the audit log"},
	{"audit:export", "O", "", "", "Exportar la auditoría", "Export the audit log"},
	{"orgvar:read", "O", "", "", "Ver variables de la cuenta (enmascaradas)", "View account variables (masked)"},
	{"orgvar:write", "O", "s", "", "Crear y borrar variables de la cuenta", "Create and delete account variables"},
	{"orgvar:reveal", "O", "s", "", "Ver valores de variables de la cuenta", "Reveal account variable values"},
	{"billing:read", "O", "", "", "Ver facturación", "View billing"},
	{"billing:manage", "O", "s", "", "Gestionar facturación", "Manage billing"},
	{"token:read-all", "O", "", "", "Ver tokens de otros miembros", "View tokens of other members"},
	{"token:revoke-any", "O", "", "", "Revocar tokens de otros miembros", "Revoke tokens of other members"},
	{"oauthclient:manage", "O", "", "", "Gestionar clientes OAuth", "Manage OAuth clients"},
	{"project:create", "O", "g", "", "Crear proyectos", "Create projects"},

	// ---- project, repo and environment (SPEC 3.2), 66 entries ----
	{"project:view", "PRE", "", "project.read", "Saber que el proyecto existe", "See that the project exists"},
	{"project:read", "P", "", "project.read", "Ver el detalle del proyecto", "View project details"},
	{"project:update", "P", "", "project.ops", "Editar ajustes del proyecto", "Edit project settings"},
	{"project:delete", "P", "s", "project.delete", "Borrar el proyecto", "Delete the project"},
	{"project:restore", "P", "s", "project.delete", "Recuperar un proyecto borrado", "Restore a deleted project"},
	{"deployment:read", "P", "", "project.read", "Ver despliegues", "View deployments"},
	{"deployment:create", "P", "", "project.deploy", "Crear despliegues", "Create deployments"},
	{"deployment:cancel", "P", "", "project.deploy", "Cancelar despliegues", "Cancel deployments"},
	{"deployment:rollback", "P", "", "project.deploy", "Revertir despliegues", "Roll back deployments"},
	{"preview:read", "P", "", "project.read", "Ver previews", "View previews"},
	{"preview:manage", "P", "", "project.deploy", "Crear y borrar previews", "Create and delete previews"},
	{"log:read", "P", "", "project.read", "Leer logs", "Read logs"},
	{"envvar:read", "P", "", "project.read", "Ver variables (enmascaradas)", "View variables (masked)"},
	{"envvar:write", "P", "", "project.env_write", "Crear y borrar variables", "Create and delete variables"},
	{"envvar:reveal", "P", "s", "project.env_reveal", "Ver valores secretos", "Reveal secret values"},
	{"environment:read", "PE", "", "env.read", "Ver entornos y promociones", "View environments and promotions"},
	{"environment:manage", "PE", "", "env.admin", "Configurar entornos y aprobadores", "Configure environments and approvers"},
	{"promotion:request", "PE", "", "env.request", "Solicitar una promoción", "Request a promotion"},
	{"promotion:approve", "PE", "s", "env.approve", "Aprobar una promoción", "Approve a promotion"},
	{"worker:read", "P", "", "project.read", "Ver workers", "View workers"},
	{"worker:manage", "P", "", "project.ops", "Gestionar workers", "Manage workers"},
	{"cron:read", "P", "", "project.read", "Ver cron jobs", "View cron jobs"},
	{"cron:manage", "P", "", "project.ops", "Crear y borrar cron jobs", "Create and delete cron jobs"},
	{"cron:trigger", "P", "", "project.ops", "Lanzar un cron job", "Trigger a cron job"},
	{"domain:read", "OP", "", "project.read", "Ver dominios", "View domains"},
	{"domain:manage", "OP", "g", "project.ops", "Gestionar dominios", "Manage domains"},
	{"email:read", "P", "", "project.read", "Ver correo (estado, estadísticas, DNS, logs)", "View email (status, stats, DNS, logs)"},
	{"email:manage", "P", "", "project.ops", "Configurar y enviar correo", "Configure and send email"},
	{"storage:read", "P", "", "project.read", "Ver buckets", "View buckets"},
	{"storage:manage", "P", "", "project.databases", "Crear y borrar buckets", "Create and delete buckets"},
	{"storage:presign", "P", "", "project.ops", "Firmar URLs de buckets", "Presign bucket URLs"},
	{"database:read", "OP", "", "project.read", "Ver bases de datos", "View databases"},
	{"database:create", "OP", "g", "project.databases", "Crear bases de datos", "Create databases"},
	{"database:delete", "P", "s", "project.databases", "Borrar bases de datos", "Delete databases"},
	{"database:query", "P", "s", "project.ops", "Usar el explorador SQL", "Use the SQL explorer"},
	{"backup:read", "P", "", "project.read", "Ver respaldos", "View backups"},
	{"backup:manage", "P", "", "project.ops", "Gestionar respaldos", "Manage backups"},
	{"backup:restore", "P", "s", "project.databases", "Restaurar respaldos", "Restore backups"},
	{"connaudit:read", "P", "", "project.read", "Ver auditoría de conexiones", "View connection audit"},
	{"connaudit:manage", "P", "", "project.ops", "Gestionar la auditoría de conexiones", "Manage connection audit"},
	{"network:read", "P", "", "project.read", "Ver reglas de red", "View network rules"},
	{"network:manage", "P", "s", "project.network", "Gestionar reglas de red", "Manage network rules"},
	{"gateway:connect", "P", "", "project.connect", "Conectarse por el gateway", "Connect through the gateway"},
	{"gateway:manage", "P", "s", "project.network", "Exponer o cerrar servicios del gateway", "Expose or close gateway services"},
	{"gateway:token", "P", "s", "project.network", "Gestionar tokens de servicio del gateway", "Manage gateway service tokens"},
	{"git:read", "PR", "", "git.read", "Leer código, ramas, commits y PR", "Read code, branches, commits and PRs"},
	{"git:write", "PR", "", "git.write", "Crear ramas, abrir PR y comentar", "Create branches, open PRs and comment"},
	{"git:review", "PR", "", "git.review", "Revisar pull requests", "Review pull requests"},
	{"git:merge", "PR", "", "git.merge", "Fusionar pull requests", "Merge pull requests"},
	{"git:link", "P", "", "project.ops", "Enlazar o crear el repositorio", "Link or create the repository"},
	{"git:protect", "PR", "s", "git.admin", "Proteger ramas", "Protect branches"},
	{"git:settings", "PR", "", "git.admin", "Ajustes del repositorio", "Repository settings"},
	{"git:mirror", "PR", "", "git.admin", "Gestionar espejos", "Manage mirrors"},
	{"git:review-dismiss", "PR", "", "git.admin", "Descartar revisiones", "Dismiss reviews"},
	{"git:token-service", "PR", "s", "git.admin", "Tokens de servicio Git", "Git service tokens"},
	{"ci:read", "PR", "", "git.read", "Ver workflows, runs y logs de CI", "View CI workflows, runs and logs"},
	{"ci:run", "PR", "", "git.write", "Lanzar, relanzar y cancelar CI", "Run, re-run and cancel CI"},
	{"ci:variable", "PR", "", "git.admin", "Variables de CI", "CI variables"},
	{"ci:secret", "PR", "s", "git.admin", "Secretos de CI", "CI secrets"},
	{"security:read", "P", "", "security.read", "Ver alertas de seguridad", "View security alerts"},
	{"security:triage", "P", "", "security.triage", "Descartar alertas bajas y medias", "Dismiss low and medium alerts"},
	{"security:upload", "P", "", "security.triage", "Subir resultados SARIF", "Upload SARIF results"},
	{"security:admin", "P", "s", "security.admin", "Alertas críticas y altas, políticas", "Critical and high alerts, policies"},
	{"webhook:manage", "P", "", "webhooks.manage", "Gestionar webhooks salientes", "Manage outbound webhooks"},
	{"assignment:read", "OP", "", "project.members", "Ver quién tiene acceso", "View who has access"},
	{"assignment:grant", "OPRE", "s", "project.members", "Asignar plantillas de acceso", "Grant access templates"},

	// ---- platform (SPEC 3.3), 7 entries ----
	{"platform-user:read", "L", "", "", "Ver usuarios de la plataforma", "View platform users"},
	{"platform-user:create", "L", "", "", "Crear usuarios de la plataforma", "Create platform users"},
	{"platform-user:suspend", "L", "", "", "Suspender usuarios de la plataforma", "Suspend platform users"},
	{"platform-user:delete", "L", "", "", "Borrar usuarios de la plataforma", "Delete platform users"},
	{"platform-user:set-role", "L", "", "", "Cambiar el rol de plataforma", "Change the platform role"},
	{"platform-backup:read", "L", "", "", "Ver respaldos de la plataforma", "View platform backups"},
	{"platform-backup:run", "L", "", "", "Ejecutar respaldos de la plataforma", "Run platform backups"},
}

var groupOf = map[string]string{
	"org": "organization", "member": "members", "group": "groups", "template": "templates",
	"assignment": "access", "audit": "audit", "orgvar": "variables", "billing": "billing",
	"token": "tokens", "oauthclient": "integrations", "project": "project",
	"deployment": "deployments", "preview": "deployments", "log": "observability",
	"envvar": "variables", "environment": "environments", "promotion": "environments",
	"worker": "runtime", "cron": "runtime", "domain": "networking", "email": "networking",
	"network": "networking", "gateway": "networking", "storage": "data", "database": "data",
	"backup": "data", "connaudit": "data", "git": "git", "ci": "git", "security": "security",
	"webhook": "integrations", "platform-user": "platform", "platform-backup": "platform",
}

// Verbs that need the read permission of their resource (SPEC 3.4).
var needsRead = map[string]bool{
	"manage": true, "write": true, "create": true, "delete": true, "run": true,
	"trigger": true, "request": true, "merge": true, "review": true,
}

// Dependencies of SPEC 3.4 that the verb rule does not express.
var explicitRequires = map[string]string{
	"envvar:reveal":     "envvar:read",
	"backup:restore":    "backup:read",
	"database:query":    "database:read",
	"promotion:approve": "environment:read",
	"assignment:grant":  "assignment:read",
}

// Resources whose permissions never travel in a token (SPEC 9.1), plus two single entries.
var nonTokenable = map[string]bool{
	"org": true, "member": true, "group": true, "template": true, "assignment": true,
	"token": true, "oauthclient": true, "platform-user": true, "platform-backup": true,
}

var (
	perms []Perm
	index map[string]int
	byOld map[string][]int
)

func init() {
	index = make(map[string]int, len(table))
	byOld = map[string][]int{}
	for i, r := range table {
		if _, dup := index[r.id]; dup {
			panic("catalog: duplicate permission " + r.id)
		}
		index[r.id] = i
	}
	if len(table) > MaxPerms {
		panic("catalog: more permissions than the Set can hold")
	}
	for i, r := range table {
		res, _, _ := strings.Cut(r.id, ":")
		p := Perm{
			ID: r.id, Bit: i, Since: 1, Group: groupOf[res],
			Sensitive: strings.Contains(r.flags, "s"),
			LegacyGap: strings.Contains(r.flags, "g"),
			Tokenable: !nonTokenable[res] && r.id != "billing:manage",
			Label:     Label{ES: r.es, EN: r.en},
			Requires:  []string{},
			Legacy:    []string{},
		}
		for _, c := range r.scopes {
			switch c {
			case 'O':
				p.Scopes = append(p.Scopes, ScopeOrg)
			case 'P':
				p.Scopes = append(p.Scopes, ScopeProject)
			case 'R':
				p.Scopes = append(p.Scopes, ScopeRepo)
			case 'E':
				p.Scopes = append(p.Scopes, ScopeEnv)
			case 'L':
				p.Scopes = append(p.Scopes, ScopePlatform)
			}
		}
		sort.Slice(p.Scopes, func(a, b int) bool { return scopeRank(p.Scopes[a]) < scopeRank(p.Scopes[b]) })
		if r.legacy != "" {
			p.Legacy = strings.Fields(r.legacy)
			for _, old := range p.Legacy {
				byOld[old] = append(byOld[old], i)
			}
		}
		perms = append(perms, p)
	}
	// Dependencies (SPEC 3.4).
	//   Rule 1: a project/repo/env permission needs project:view. Permissions that are ALSO valid at
	//           organization scope do not: organization templates carry no project:view.
	//   Rule 2: write-like verbs (and every git:*, ci:*, security:*, member:* but the read itself) need the
	//           :read of the same resource when it exists with a shared scope.
	for i := range perms {
		p := &perms[i]
		res, verb, _ := strings.Cut(p.ID, ":")
		var req []string
		add := func(id string) {
			if id == p.ID {
				return
			}
			for _, x := range req {
				if x == id {
					return
				}
			}
			req = append(req, id)
		}
		if p.ID != "project:view" && !p.HasScope(ScopeOrg) && !p.HasScope(ScopePlatform) {
			add("project:view")
		}
		if verb != "read" && (needsRead[verb] || res == "git" || res == "ci" || res == "security" || res == "member") {
			if j, ok := index[res+":read"]; ok && sharesScope(p, &perms[j]) {
				add(res + ":read")
			}
		}
		if e, ok := explicitRequires[p.ID]; ok {
			add(e)
		}
		sort.Strings(req)
		if req != nil {
			p.Requires = req
		}
	}
}

func scopeRank(s Scope) int {
	switch s {
	case ScopeOrg:
		return 0
	case ScopeProject:
		return 1
	case ScopeRepo:
		return 2
	case ScopeEnv:
		return 3
	}
	return 4
}

func sharesScope(a, b *Perm) bool {
	for _, s := range a.Scopes {
		if b.HasScope(s) {
			return true
		}
	}
	return false
}

func clone(p Perm) Perm {
	p.Scopes = append([]Scope(nil), p.Scopes...)
	p.Requires = append([]string{}, p.Requires...)
	p.Legacy = append([]string{}, p.Legacy...)
	return p
}

// All returns every catalog entry in bit order. The slice is a copy.
func All() []Perm {
	out := make([]Perm, len(perms))
	for i, p := range perms {
		out[i] = clone(p)
	}
	return out
}

// Len is the number of catalog entries.
func Len() int { return len(perms) }

// Has reports whether id is a catalog permission.
func Has(id string) bool { _, ok := index[id]; return ok }

// Get returns the entry for id.
func Get(id string) (Perm, bool) {
	i, ok := index[id]
	if !ok {
		return Perm{}, false
	}
	return clone(perms[i]), true
}

// Bit returns the bit position of id in a Set.
func Bit(id string) (int, bool) { i, ok := index[id]; return i, ok }

// IDAt returns the permission at bit position b ("" when out of range).
func IDAt(b int) string {
	if b < 0 || b >= len(perms) {
		return ""
	}
	return perms[b].ID
}

// Expand returns the atomic permissions an old authz action expands to (SPEC 3.2 note 1), in catalog
// order. The system roles hold the COMPLETE expansion of every old action they grant. It returns nil for
// a string that is not an old action. It is generic over string kinds so callers pass an authz.Action
// directly without this package importing authz.
func Expand[A ~string](old A) []string {
	ix := byOld[string(old)]
	if len(ix) == 0 {
		return nil
	}
	out := make([]string, len(ix))
	for i, j := range ix {
		out[i] = perms[j].ID
	}
	return out
}

// ExpandSet is the union of the expansions of several old actions, as a Set.
func ExpandSet[A ~string](olds ...A) Set {
	var s Set
	for _, o := range olds {
		for _, j := range byOld[string(o)] {
			s = s.addBit(j)
		}
	}
	return s
}

// OldActions returns the old authz actions that have an expansion, sorted.
func OldActions() []string {
	out := make([]string, 0, len(byOld))
	for k := range byOld {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Match expands a wildcard pattern ("*", "resource:*") or a plain id to catalog ids, in catalog order.
// Wildcards are only valid in system templates (SPEC 3.0).
func Match(pattern string) []string {
	var out []string
	switch {
	case pattern == "*":
		for _, p := range perms {
			out = append(out, p.ID)
		}
	case strings.HasSuffix(pattern, ":*"):
		pre := strings.TrimSuffix(pattern, "*")
		for _, p := range perms {
			if strings.HasPrefix(p.ID, pre) {
				out = append(out, p.ID)
			}
		}
	default:
		if Has(pattern) {
			out = []string{pattern}
		}
	}
	return out
}
