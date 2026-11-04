package access

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kynto/capsule/backend/internal/authz/catalog"
	"github.com/kynto/capsule/backend/internal/authz/engine"
)

// ---------------------------------------------------------------- catalog

// CatalogEntry is one entry of GET /permissions/catalog.
type CatalogEntry struct {
	ID         string            `json:"id"`
	Scopes     []string          `json:"scopes"`
	Group      string            `json:"group"`
	Sensitive  bool              `json:"sensitive"`
	Tokenable  bool              `json:"tokenable"`
	Requires   []string          `json:"requires"`
	Legacy     []string          `json:"legacy"`
	Since      int               `json:"since"`
	Deprecated bool              `json:"deprecated"`
	Label      map[string]string `json:"label"`
}

// CatalogGroup is a UI group of permissions.
type CatalogGroup struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// CatalogDoc is the body of GET /permissions/catalog.
type CatalogDoc struct {
	CatalogVersion int            `json:"catalog_version"`
	Groups         []CatalogGroup `json:"groups"`
	Permissions    []CatalogEntry `json:"permissions"`
}

var (
	catalogOnce sync.Once
	catalogBody []byte
	catalogTag  string
)

// CatalogJSON returns the catalog document and its ETag (the catalog lives in code and never changes while the process runs).
func CatalogJSON() ([]byte, string) {
	catalogOnce.Do(func() {
		doc := CatalogDoc{CatalogVersion: catalog.Version, Groups: []CatalogGroup{}, Permissions: []CatalogEntry{}}
		seen := map[string]bool{}
		for _, p := range catalog.All() {
			scopes := make([]string, len(p.Scopes))
			for i, sc := range p.Scopes {
				scopes[i] = string(sc)
			}
			doc.Permissions = append(doc.Permissions, CatalogEntry{
				ID: p.ID, Scopes: scopes, Group: p.Group, Sensitive: p.Sensitive, Tokenable: p.Tokenable,
				Requires: nonNilStrings(p.Requires), Legacy: nonNilStrings(p.Legacy), Since: p.Since, Deprecated: p.Deprecated,
				Label: map[string]string{"es": p.Label.ES, "en": p.Label.EN},
			})
			if !seen[p.Group] {
				seen[p.Group] = true
				label := p.Group
				if label != "" {
					label = strings.ToUpper(label[:1]) + label[1:]
				}
				doc.Groups = append(doc.Groups, CatalogGroup{ID: p.Group, Label: label})
			}
		}
		catalogBody, _ = json.Marshal(doc)
		sum := sha256.Sum256(catalogBody)
		catalogTag = `"` + hex.EncodeToString(sum[:16]) + `"`
	})
	return catalogBody, catalogTag
}

// ---------------------------------------------------------------- /me/permissions

// ProjectMask is one entry of the sparse per-project map.
type ProjectMask struct {
	Mask   string `json:"mask"`
	Source string `json:"source"`
}

// MyOrgTemplate is the organization template of the person.
type MyOrgTemplate struct {
	Slug    string `json:"slug"`
	Version int    `json:"version"`
	Label   string `json:"label"`
	System  bool   `json:"system"`
}

// MyOrg is the organization block of MyPermissions.
type MyOrg struct {
	ID          uuid.UUID      `json:"id"`
	Slug        string         `json:"slug"`
	Status      string         `json:"status"`
	Template    *MyOrgTemplate `json:"template"`
	Permissions []string       `json:"permissions"`
}

// MyUser is the account block of MyPermissions.
type MyUser struct {
	ID     uuid.UUID `json:"id"`
	Status string    `json:"status"`
}

// MyPermissions is the MyPermissions schema (SPEC 11.1), the source of the sidebar and of useCan.
//
// ProjectDefault is what the person holds in a project with no assignments of its own. With expand=projects, Projects lists the
// projects whose access differs from that default (a different mask, or own assignments); any project not listed has ProjectDefault
// (visible exactly when it contains project:view). That keeps the answer small for organizations with thousands of projects.
type MyPermissions struct {
	CatalogVersion int                    `json:"catalog_version"`
	Epoch          int64                  `json:"epoch"`
	User           MyUser                 `json:"user"`
	Platform       []string               `json:"platform"`
	Org            *MyOrg                 `json:"org,omitempty"`
	ProjectDefault []string               `json:"project_default"`
	Aggregate      []string               `json:"aggregate"`
	Permissions    *[]string              `json:"permissions,omitempty"`
	ProjectSource  string                 `json:"project_source,omitempty"`
	CatalogIndex   []string               `json:"catalog_index,omitempty"`
	Projects       map[string]ProjectMask `json:"projects,omitempty"`
	ProjectsSparse bool                   `json:"projects_sparse,omitempty"`
}

// MeResult is a rendered /me/permissions answer.
type MeResult struct {
	Body  []byte
	ETag  string
	Epoch int64
}

type meKey struct {
	user, org, project uuid.UUID
	expand             bool
}

type meEntry struct {
	orgEpoch, userEpoch int64
	at                  time.Time
	res                 *MeResult
}

type meCache struct {
	mu sync.Mutex
	m  map[meKey]meEntry
}

func newMeCache() *meCache { return &meCache{m: map[meKey]meEntry{}} }

const meTTL = 10 * time.Second

func (c *meCache) get(k meKey) (meEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[k]
	return e, ok
}

func (c *meCache) put(k meKey, e meEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) > 20000 {
		c.m = map[meKey]meEntry{}
	}
	c.m[k] = e
}

func (c *meCache) purgeOrg(org uuid.UUID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.m {
		if k.org == org {
			delete(c.m, k)
		}
	}
}

// probeProject stands for "a project with no assignments of its own" when asking the engine for project_default.
var probeProject = uuid.MustParse("00000000-0000-0000-0000-00000000dead")

// ResolveOrg turns an id or slug into an organization id; "" picks the oldest membership of the user. It returns uuid.Nil without an
// error when the user has no organization (and none was asked for).
func (s *Service) ResolveOrg(ctx context.Context, user uuid.UUID, ref string) (uuid.UUID, error) {
	var id uuid.UUID
	var err error
	switch {
	case ref == "":
		err = s.q().QueryRow(ctx, `SELECT om.org_id FROM org_members om JOIN organizations o ON o.id = om.org_id AND o.deleted_at IS NULL
			WHERE om.user_id = $1 ORDER BY om.joined_at, om.org_id LIMIT 1`, user).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, nil
		}
	default:
		if u, perr := uuid.Parse(ref); perr == nil {
			err = s.q().QueryRow(ctx, `SELECT id FROM organizations WHERE id = $1 AND deleted_at IS NULL`, u).Scan(&id)
		} else {
			err = s.q().QueryRow(ctx, `SELECT id FROM organizations WHERE slug = $1 AND deleted_at IS NULL`, ref).Scan(&id)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, notFound("organization not found")
		}
	}
	return id, err
}

// MyPermissions answers GET /me/permissions for the authenticated user (self scope: no permission needed). A user who is not a member
// of the organization gets the same 404 as for an organization that does not exist.
func (s *Service) MyPermissions(ctx context.Context, user uuid.UUID, orgRef, project, expand string) (*MeResult, error) {
	org, err := s.ResolveOrg(ctx, user, orgRef)
	if err != nil {
		return nil, err
	}
	var pid *uuid.UUID
	if project != "" {
		u, perr := uuid.Parse(project)
		if perr != nil {
			return nil, validationField("project", "must be a uuid")
		}
		pid = &u
	}
	if expand != "" && expand != "projects" {
		return nil, validationField("expand", "must be projects")
	}
	return s.permissionsOf(ctx, user, org, pid, expand == "projects", true)
}

// UserPermissions answers GET /orgs/{org}/users/{user}/permissions (assignment:read).
func (s *Service) UserPermissions(ctx context.Context, actor Actor, org, target uuid.UUID, project, expand string) (*MeResult, error) {
	if _, err := s.require(ctx, actor, org, orgScope, "assignment:read"); err != nil {
		return nil, err
	}
	var pid *uuid.UUID
	if project != "" {
		u, perr := uuid.Parse(project)
		if perr != nil {
			return nil, validationField("project", "must be a uuid")
		}
		// only projects the actor can see
		if _, _, _, err := s.requireAt(ctx, actor, org, "project", u, "assignment:read"); err != nil {
			return nil, err
		}
		pid = &u
	}
	if expand != "" && expand != "projects" {
		return nil, validationField("expand", "must be projects")
	}
	return s.permissionsOf(ctx, target, org, pid, expand == "projects", true)
}

func (s *Service) permissionsOf(ctx context.Context, user, org uuid.UUID, project *uuid.UUID, expand, useCache bool) (*MeResult, error) {
	if org == uuid.Nil {
		return s.noOrgPermissions(ctx, user)
	}
	key := meKey{user: user, org: org, expand: expand}
	if project != nil {
		key.project = *project
	}
	oe, ue, err := s.store.Epochs(ctx, org, user)
	if err != nil {
		return nil, err
	}
	if useCache {
		if e, ok := s.me.get(key); ok && e.orgEpoch == oe && e.userEpoch == ue && s.now().Sub(e.at) < meTTL {
			return e.res, nil
		}
	}
	mp, err := s.computePermissions(ctx, user, org, project, expand, oe)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(mp)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	res := &MeResult{Body: body, ETag: `"` + hex.EncodeToString(sum[:16]) + `"`, Epoch: oe}
	if useCache {
		s.me.put(key, meEntry{orgEpoch: oe, userEpoch: ue, at: s.now(), res: res})
	}
	return res, nil
}

func (s *Service) noOrgPermissions(ctx context.Context, user uuid.UUID) (*MeResult, error) {
	var status, role string
	if err := s.q().QueryRow(ctx, `SELECT status, platform_role FROM users WHERE id = $1`, user).Scan(&status, &role); err != nil {
		return nil, err
	}
	mp := &MyPermissions{CatalogVersion: catalog.Version, User: MyUser{ID: user, Status: status}, Platform: platformPerms(status, role),
		ProjectDefault: []string{}, Aggregate: []string{}}
	body, err := json.Marshal(mp)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	return &MeResult{Body: body, ETag: `"` + hex.EncodeToString(sum[:16]) + `"`}, nil
}

func platformPerms(status, role string) []string {
	if role != "admin" || status != "active" {
		return []string{}
	}
	var out []string
	for _, p := range catalog.All() {
		if p.HasScope(catalog.ScopePlatform) {
			out = append(out, p.ID)
		}
	}
	return nonNilStrings(out)
}

func (s *Service) computePermissions(ctx context.Context, user, org uuid.UUID, project *uuid.UUID, expand bool, epoch int64) (*MyPermissions, error) {
	var slug, ustatus, prole string
	var mstatus string
	var tid *uuid.UUID
	var tver *int
	err := s.q().QueryRow(ctx, `
		SELECT o.slug, u.status, u.platform_role, om.status, om.template_id, om.template_version
		  FROM org_members om JOIN organizations o ON o.id = om.org_id AND o.deleted_at IS NULL JOIN users u ON u.id = om.user_id
		 WHERE om.org_id = $1 AND om.user_id = $2`, org, user).Scan(&slug, &ustatus, &prole, &mstatus, &tid, &tver)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("organization not found")
	}
	if err != nil {
		return nil, err
	}
	mp := &MyPermissions{CatalogVersion: catalog.Version, Epoch: epoch, User: MyUser{ID: user, Status: ustatus}, Platform: platformPerms(ustatus, prole)}
	orgStatus := "active"
	if ustatus != "active" || mstatus != "active" {
		orgStatus = "suspended"
	}
	mo := &MyOrg{ID: org, Slug: slug, Status: orgStatus}
	if tid != nil {
		v := 0
		if tver != nil {
			v = *tver
		}
		if h, err := loadHead(ctx, s.q(), org, *tid, false); err == nil {
			if ver, err := loadVer(ctx, s.q(), *tid, v); err == nil {
				mo.Template = &MyOrgTemplate{Slug: h.Slug, Version: ver.Version, Label: h.Name, System: h.System}
			}
		}
	}
	_, oset, err := s.eng.Effective(ctx, user, org, engine.OrgScope())
	if err != nil {
		return nil, err
	}
	mo.Permissions = nonNilStrings(oset.IDs())
	mp.Org = mo

	dacc, dset, err := s.eng.Effective(ctx, user, org, engine.ProjectScope(probeProject))
	if err != nil {
		return nil, err
	}
	if dacc.Hidden {
		dset = catalog.Set{}
	}
	mp.ProjectDefault = nonNilStrings(dset.IDs())

	ids, err := s.projectIDs(ctx, s.q(), org)
	if err != nil {
		return nil, err
	}
	var agg catalog.Set
	sparse := map[string]ProjectMask{}
	defMask := dset.Hex()
	for _, id := range ids {
		acc, set, err := s.eng.Effective(ctx, user, org, engine.ProjectScope(id))
		if err != nil {
			return nil, err
		}
		if acc.Hidden {
			set = catalog.Set{}
		}
		agg = agg.Union(set)
		if expand {
			mask := set.Hex()
			if mask != defMask || (!acc.Hidden && acc.Source == engine.SourceExplicit) {
				sparse[id.String()] = ProjectMask{Mask: mask, Source: string(acc.Source)}
			}
		}
	}
	mp.Aggregate = nonNilStrings(agg.IDs())
	if expand {
		idx := make([]string, catalog.Len())
		for i := range idx {
			idx[i] = catalog.IDAt(i)
		}
		mp.CatalogIndex = idx
		mp.Projects = sparse
		mp.ProjectsSparse = true
	}
	if project != nil {
		ok := false
		for _, id := range ids {
			if id == *project {
				ok = true
				break
			}
		}
		if !ok {
			return nil, notFound("project not found")
		}
		acc, set, err := s.eng.Effective(ctx, user, org, engine.ProjectScope(*project))
		if err != nil {
			return nil, err
		}
		if acc.Hidden {
			return nil, notFound("project not found")
		}
		p := nonNilStrings(set.IDs())
		mp.Permissions = &p
		mp.ProjectSource = string(acc.Source)
	}
	return mp, nil
}

// sortedIDs returns the ids in catalog order (for stable outputs).
func sortedIDs(ids []string) []string {
	out := append([]string(nil), ids...)
	sort.Slice(out, func(i, j int) bool {
		a, _ := catalog.Bit(out[i])
		b, _ := catalog.Bit(out[j])
		return a < b
	})
	return out
}
