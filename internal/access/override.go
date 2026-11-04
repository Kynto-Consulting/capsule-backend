package access

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kynto/capsule/backend/internal/authz/catalog"
	"github.com/kynto/capsule/backend/internal/authz/engine"
	"github.com/kynto/capsule/backend/internal/authz/systemtemplates"
	"github.com/kynto/capsule/backend/internal/domain"
)

// OverrideResult is the answer of PUT .../access-override.
type OverrideResult struct {
	Mode          *string `json:"mode"`
	EffectiveMode string  `json:"effective_mode"`
}

// maxWouldHideScan bounds the members evaluated by the visibility preview.
const maxWouldHideScan = 5000

// wouldHide returns the members who see the project now and would not with the policy change, using the SAME engine over an overlay.
func (s *Service) wouldHide(ctx context.Context, org, project uuid.UUID, newMode *string) ([]UserRef, error) {
	rows, err := s.q().Query(ctx, `SELECT user_id FROM org_members WHERE org_id = $1 ORDER BY user_id LIMIT $2`, org, maxWouldHideScan+1)
	if err != nil {
		return nil, err
	}
	var members []uuid.UUID
	for rows.Next() {
		var u uuid.UUID
		if err := rows.Scan(&u); err != nil {
			rows.Close()
			return nil, err
		}
		members = append(members, u)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(members) > maxWouldHideScan {
		return nil, limitErr("the organization is too large to preview the visibility change")
	}
	hyp := s.overlayEngine(func(d *engine.AccessData) {
		if newMode == nil {
			delete(d.ProjectOverrides, project)
			return
		}
		if d.ProjectOverrides == nil {
			d.ProjectOverrides = map[uuid.UUID]string{}
		}
		d.ProjectOverrides[project] = *newMode
	})
	var (
		mu    sync.Mutex
		hide  []uuid.UUID
		first error
		wg    sync.WaitGroup
	)
	sem := make(chan struct{}, 8)
	for _, u := range members {
		u := u
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			cur, _, err := s.eng.Effective(ctx, u, org, engine.ProjectScope(project))
			if err == nil && cur.Member && !cur.Hidden {
				var nxt engine.Access
				nxt, _, err = hyp.Effective(ctx, u, org, engine.ProjectScope(project))
				if err == nil && nxt.Hidden {
					mu.Lock()
					hide = append(hide, u)
					mu.Unlock()
				}
			}
			if err != nil {
				mu.Lock()
				if first == nil {
					first = err
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if first != nil {
		return nil, first
	}
	refs, err := s.userRefs(ctx, s.q(), hide)
	if err != nil {
		return nil, err
	}
	out := make([]UserRef, 0, len(hide))
	for _, id := range hide {
		out = append(out, refs[id])
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Email != out[j].Email {
			return out[i].Email < out[j].Email
		}
		return out[i].ID.String() < out[j].ID.String()
	})
	return out, nil
}

// SetAccessOverride sets, changes or clears (nil) the access policy override of a project (org:access-policy). Moving a project to
// restricted first computes who would lose visibility, the actor included; without confirm the answer is 409 WOULD_HIDE with the list.
func (s *Service) SetAccessOverride(ctx context.Context, actor Actor, org, project uuid.UUID, mode *string, confirm bool, idem *Idem) (Reply[*OverrideResult], error) {
	fail := func(err error) (Reply[*OverrideResult], error) { return Reply[*OverrideResult]{}, err }
	if _, err := s.require(ctx, actor, org, orgScope, "org:access-policy"); err != nil {
		return fail(err)
	}
	if mode != nil && *mode != "open" && *mode != "restricted" {
		return fail(validationField("mode", "must be open, restricted or null"))
	}
	// a project that does not exist and one the actor cannot see are the same 404
	var exists bool
	if err := s.q().QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM projects WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL)`, project, org).Scan(&exists); err != nil {
		return fail(err)
	}
	acc, _, err := s.eng.Effective(ctx, actor.UserID, org, engine.ProjectScope(project))
	if err != nil {
		return fail(err)
	}
	if !exists || acc.Hidden {
		return fail(notFound("project not found"))
	}
	var orgMode string
	var oldOverride *string
	if err := s.q().QueryRow(ctx, `SELECT o.project_access_mode, p.access_override FROM organizations o JOIN projects p ON p.org_id = o.id WHERE o.id = $1 AND p.id = $2`, org, project).Scan(&orgMode, &oldOverride); err != nil {
		return fail(err)
	}
	effOld, effNew := orgMode, orgMode
	if oldOverride != nil {
		effOld = *oldOverride
	}
	if mode != nil {
		effNew = *mode
	}
	var hide []UserRef
	if effNew == "restricted" && effOld != "restricted" {
		if hide, err = s.wouldHide(ctx, org, project, mode); err != nil {
			return fail(err)
		}
		if len(hide) > 0 && !confirm {
			list := hide
			if len(list) > 200 {
				list = list[:200]
			}
			return fail(conflict("WOULD_HIDE", "this change would hide the project from people who see it now; repeat with confirm=true", map[string]any{
				"would_hide": list, "would_hide_count": len(hide)}))
		}
	}
	return doWrite(ctx, s, org, actor, idem, 200, func(tx pgx.Tx) (*OverrideResult, error) {
		tag, err := tx.Exec(ctx, `UPDATE projects SET access_override = $3 WHERE id = $2 AND org_id = $1 AND deleted_at IS NULL`, org, project, mode)
		if err != nil {
			return nil, mapPg(err)
		}
		if tag.RowsAffected() == 0 {
			return nil, domain.ErrNotFound
		}
		if (oldOverride == nil) != (mode == nil) || (oldOverride != nil && mode != nil && *oldOverride != *mode) {
			if err := s.audit(ctx, tx, org, actor, auditRow{Action: "access.mode.changed", ResourceType: "org_policy", ResourceID: project, ProjectID: &project,
				Old: map[string]any{"mode": oldOverride, "effective_mode": effOld}, New: map[string]any{"mode": mode, "effective_mode": effNew},
				Impact: len(hide)}); err != nil {
				return nil, err
			}
		}
		return &OverrideResult{Mode: mode, EffectiveMode: effNew}, nil
	})
}

// OrgMemberDTO is the OrgMember schema.
type OrgMemberDTO struct {
	User     UserRef          `json:"user"`
	Role     string           `json:"role"`
	Template *OrgMemberTplDTO `json:"template"`
	Status   string           `json:"status"`
	Groups   []string         `json:"groups"`
	JoinedAt time.Time        `json:"joined_at"`
}

// OrgMemberTplDTO is the template block of an OrgMember.
type OrgMemberTplDTO struct {
	Slug    string `json:"slug"`
	Version int    `json:"version"`
	System  bool   `json:"system"`
}

func (s *Service) loadOrgMember(ctx context.Context, q querier, org, user uuid.UUID) (*OrgMemberDTO, error) {
	var m OrgMemberDTO
	var slug *string
	var ver *int
	var system *bool
	var cur *int
	err := q.QueryRow(ctx, `
		SELECT u.id, u.email, u.name, om.role, om.status, om.joined_at, t.slug, om.template_version, t.system, t.current_version
		  FROM org_members om JOIN users u ON u.id = om.user_id LEFT JOIN role_templates t ON t.id = om.template_id
		 WHERE om.org_id = $1 AND om.user_id = $2`, org, user).Scan(&m.User.ID, &m.User.Email, &m.User.Name, &m.Role, &m.Status, &m.JoinedAt, &slug, &ver, &system, &cur)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if slug != nil {
		v := 0
		if ver != nil {
			v = *ver
		} else if cur != nil {
			v = *cur
		}
		m.Template = &OrgMemberTplDTO{Slug: *slug, Version: v, System: system != nil && *system}
	}
	rows, err := q.Query(ctx, `SELECT g.slug FROM group_members gm JOIN groups g ON g.id = gm.group_id AND g.org_id = $1 AND g.archived_at IS NULL WHERE gm.user_id = $2 ORDER BY g.slug`, org, user)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m.Groups = []string{}
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err != nil {
			return nil, err
		}
		m.Groups = append(m.Groups, g)
	}
	return &m, rows.Err()
}

// legacyLabel is the org_members.role label of a template. System templates carry their own slug; a custom template is labelled
// conservatively (member when it holds every permission of the system member template, otherwise readonly; never admin or owner) because
// the legacy decision path reads only this label.
func (s *Service) legacyLabel(ctx context.Context, q querier, h *templateHead, v *templateVer) (string, error) {
	if h.System {
		return h.Slug, nil
	}
	var perms []string
	err := q.QueryRow(ctx, `SELECT v.permissions FROM role_templates t JOIN role_template_versions v ON v.template_id = t.id AND v.version = t.current_version
		WHERE t.system AND t.kind = 'org' AND t.slug = 'member'`).Scan(&perms)
	if err != nil {
		return "readonly", nil
	}
	if catalog.NewSet(v.Permissions...).ContainsAll(catalog.NewSet(perms...)) {
		return "member", nil
	}
	return "readonly", nil
}

// SetMemberTemplate changes the organization template of a person (member:update). Owners are only made or unmade by owners, nobody
// changes their own, the permissions of the new template must be held by the actor, and the last active owner cannot be demoted.
func (s *Service) SetMemberTemplate(ctx context.Context, actor Actor, org, user uuid.UUID, slug string, idem *Idem) (Reply[*OrgMemberDTO], error) {
	fail := func(err error) (Reply[*OrgMemberDTO], error) { return Reply[*OrgMemberDTO]{}, err }
	orgSet, err := s.require(ctx, actor, org, orgScope, "member:update")
	if err != nil {
		return fail(err)
	}
	if !slugRE.MatchString(slug) {
		return fail(validationField("template", "a template slug is required"))
	}
	cur, err := s.loadOrgMember(ctx, s.q(), org, user)
	if err != nil {
		return fail(notFound("member not found"))
	}
	var tid uuid.UUID
	var archived bool
	err = s.q().QueryRow(ctx, `SELECT id, archived_at IS NOT NULL FROM role_templates WHERE kind = 'org' AND slug = $2 AND (org_id = $1 OR system) ORDER BY system LIMIT 1`, org, slug).Scan(&tid, &archived)
	if errors.Is(err, pgx.ErrNoRows) {
		return fail(validationField("template", "no such organization template"))
	}
	if err != nil {
		return fail(err)
	}
	if archived {
		return fail(conflict("TEMPLATE_ARCHIVED", "template is archived", nil))
	}
	h, err := loadHead(ctx, s.q(), org, tid, false)
	if err != nil {
		return fail(Normalize(err))
	}
	ver, err := loadVer(ctx, s.q(), tid, 0)
	if err != nil {
		return fail(Normalize(err))
	}
	if !h.System {
		st, err := s.orgSettings(ctx, s.q(), org)
		if err != nil {
			return fail(err)
		}
		if !st.CustomRoles {
			return fail(validationField("template", "custom roles are not enabled for this organization"))
		}
	}
	owner, err := s.isOwner(ctx, s.q(), org, actor.UserID)
	if err != nil {
		return fail(err)
	}
	ownerTpl := systemtemplates.ID(systemtemplates.KindOrg, "owner")
	targetIsOwner := cur.Template != nil && cur.Template.System && cur.Template.Slug == "owner"
	if actor.UserID == user {
		return fail(forbidden("you cannot change your own role"))
	}
	if targetIsOwner && !owner {
		return fail(forbidden("only an owner can change an owner"))
	}
	if tid == ownerTpl && !owner {
		return fail(escalation("only an owner can assign the owner template", nil, "owner_required"))
	}
	if !owner {
		p := &preparedTemplate{Perms: catalog.NewSet(ver.Permissions...)}
		if ver.FloorID != nil {
			if fv, err := loadVer(ctx, s.q(), *ver.FloorID, 0); err == nil {
				p.FloorID, p.FloorSet = ver.FloorID, catalog.NewSet(fv.Permissions...)
			}
		}
		if ver.BaseID != nil {
			if bv, err := loadVer(ctx, s.q(), *ver.BaseID, 0); err == nil {
				p.BaseID, p.BaseSet = ver.BaseID, catalog.NewSet(bv.Permissions...)
			}
		}
		if err := s.checkNoEscalation(ctx, actor, org, "org", orgSet, p); err != nil {
			return fail(err)
		}
	}
	label, err := s.legacyLabel(ctx, s.q(), h, ver)
	if err != nil {
		return fail(err)
	}
	return doWrite(ctx, s, org, actor, idem, 200, func(tx pgx.Tx) (*OrgMemberDTO, error) {
		// the organization row is locked by InTx: two simultaneous demotions are serialized and the second sees the first
		var wasOwner bool
		if err := tx.QueryRow(ctx, `SELECT template_id = $3 FROM org_members WHERE org_id = $1 AND user_id = $2 FOR UPDATE`, org, user, ownerTpl).Scan(&wasOwner); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, domain.ErrNotFound
			}
			return nil, err
		}
		if wasOwner && tid != ownerTpl {
			var owners int
			if err := tx.QueryRow(ctx, `
				SELECT count(*) FROM org_members om JOIN users u ON u.id = om.user_id AND u.status = 'active'
				 WHERE om.org_id = $1 AND om.status = 'active' AND om.template_id = $2`, org, ownerTpl).Scan(&owners); err != nil {
				return nil, err
			}
			if owners <= 1 {
				return nil, conflict("LAST_OWNER", "an organization needs at least one active owner", nil)
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE org_members SET template_id = $3, template_version = NULL, role = $4 WHERE org_id = $1 AND user_id = $2`, org, user, tid, label); err != nil {
			return nil, mapPg(err)
		}
		old := map[string]any{"user_id": user.String(), "subject_id": user.String()}
		if cur.Template != nil {
			old["template"], old["role"] = cur.Template.Slug, cur.Role
		}
		if err := s.audit(ctx, tx, org, actor, auditRow{Action: "access.org_member.role_changed", ResourceType: "org_member", ResourceID: user,
			Old: old, New: map[string]any{"user_id": user.String(), "subject_id": user.String(), "template": slug, "role": label}, Impact: 1}); err != nil {
			return nil, err
		}
		return s.loadOrgMember(ctx, tx, org, user)
	})
}
