package gitprotect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitsource"
)

// Service implements the A4 behaviour. Safe for concurrent use.
type Service struct {
	store Store
	forge Forge
	cfg   Config
	log   *slog.Logger
	now   func() time.Time

	locks sync.Map // projectID -> *sync.Mutex

	seenMu sync.Mutex
	seen   map[string]time.Time // audit de-duplication of unmanaged Forgejo rules
}

// New builds a Service. logger may be nil.
func New(store Store, forge Forge, cfg Config, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	return &Service{store: store, forge: forge, cfg: cfg, log: logger, now: time.Now, seen: map[string]time.Time{}}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func (s *Service) ref(t Target) gitcore.RepoRef {
	return gitcore.RepoRef{Owner: t.OrgSlug, Repo: t.ProjectSlug}
}

func (s *Service) lock(id uuid.UUID) func() {
	v, _ := s.locks.LoadOrStore(id, &sync.Mutex{})
	m := v.(*sync.Mutex)
	m.Lock()
	return m.Unlock
}

func bg(ctx context.Context) context.Context { return context.WithoutCancel(ctx) }

// describe renders an error for sync_error / audit without leaking anything: gitcore errors are
// already scrubbed (code + safe message); anything else is reduced to a generic text.
func describe(err error) string {
	if e, ok := gitcore.AsError(err); ok {
		if e.Message == "" {
			return string(e.Code)
		}
		return string(e.Code) + ": " + e.Message
	}
	return "error interno"
}

func ruleValues(r Rule) map[string]any {
	b, _ := json.Marshal(r)
	m := map[string]any{}
	_ = json.Unmarshal(b, &m)
	return m
}

func (s *Service) audit(ctx context.Context, e AuditEntry) {
	if err := s.store.WriteAudit(bg(ctx), e); err != nil {
		s.log.Error("gitprotect: audit write failed", "action", e.Action, "err", err)
	}
}

func view(r Rule, st *SyncState, warns []string) Protection {
	p := Protection{Rule: r, SyncStatus: SyncPending, Warnings: warns}
	if p.RequiredChecks == nil {
		p.RequiredChecks = []string{}
	}
	if p.PushAllowRoles == nil {
		p.PushAllowRoles = []string{}
	}
	if p.MergeAllowRoles == nil {
		p.MergeAllowRoles = []string{}
	}
	if st != nil {
		p.SyncStatus = st.Status
		p.ForgejoSynced = st.Status == SyncSynced
		if st.Status != SyncSynced {
			p.SyncError = st.LastError
		}
		p.LastSyncedAt = st.LastSyncedAt
		p.DriftCount = st.DriftCount
	}
	return p
}

// ---- reads -------------------------------------------------------------------------------

// List returns the rules of the project, oldest first, with their sync state. It reads only
// Capsule's database (fast, works with Forgejo down).
func (s *Service) List(ctx context.Context, t Target) ([]Protection, error) {
	rules, err := s.store.ListRules(ctx, t.ProjectID)
	if err != nil {
		return nil, err
	}
	syncs, err := s.store.ListSync(ctx, t.ProjectID)
	if err != nil {
		return nil, err
	}
	out := make([]Protection, 0, len(rules))
	for _, r := range rules {
		var st *SyncState
		if v, ok := syncs[r.ID]; ok {
			v := v
			st = &v
		}
		out = append(out, view(r, st, nil))
	}
	return out, nil
}

// ---- writes ------------------------------------------------------------------------------

// Create stores a new rule and projects it to Forgejo. A Forgejo failure does not undo the rule:
// it is kept (source of truth) with forgejo_synced=false and sync_error, and the reconciler retries.
func (s *Service) Create(ctx context.Context, t Target, a Actor, in Input) (*Protection, error) {
	rule, warns, err := Normalize(in)
	if err != nil {
		return nil, err
	}
	warns = append(warns, unknownContextWarnings(rule)...)
	defer s.lock(t.ProjectID)()

	existing, err := s.store.ListRules(ctx, t.ProjectID)
	if err != nil {
		return nil, err
	}
	if len(existing) >= MaxRulesPerProject {
		return nil, &ConflictError{Code: "RULE_LIMIT", Message: fmt.Sprintf("un proyecto admite como máximo %d reglas de protección", MaxRulesPerProject)}
	}
	rule.ID, rule.ProjectID = uuid.New(), t.ProjectID
	if a.UserID != uuid.Nil {
		id := a.UserID
		rule.CreatedBy = &id
	}
	nv := ruleValues(rule)
	nv["op"] = "create"
	e := AuditEntry{OrgID: t.OrgID, UserID: a.UserID, Action: ActionProtectionChange, ResourceType: ResourceProtection, ResourceID: rule.ID, IP: a.IP, NewValues: nv}
	if err := s.store.CreateRule(ctx, &rule, e); err != nil {
		if errors.Is(err, ErrDuplicate) {
			return nil, &ConflictError{Code: "DUPLICATE_PATTERN", Message: "ya existe una regla con el patrón «" + rule.Pattern + "»"}
		}
		return nil, err
	}
	st := SyncState{RuleID: rule.ID, ProjectID: t.ProjectID, Status: SyncPending}
	s.project(ctx, t, rule, &st)
	all := append(existing, rule)
	if err := s.applyRepoEffects(ctx, t, all, a); err != nil {
		s.markError(ctx, &st, "ajustes del repositorio: "+describe(err))
	}
	p := view(rule, &st, warns)
	return &p, nil
}

// Replace (PUT) replaces the rule completely; omitted fields take the safe defaults.
func (s *Service) Replace(ctx context.Context, t Target, a Actor, id uuid.UUID, in Input) (*Protection, error) {
	rule, warns, err := Normalize(in)
	if err != nil {
		return nil, err
	}
	warns = append(warns, unknownContextWarnings(rule)...)
	defer s.lock(t.ProjectID)()

	old, err := s.store.GetRule(ctx, t.ProjectID, id)
	if err != nil {
		return nil, err
	}
	before, err := s.store.ListRules(ctx, t.ProjectID)
	if err != nil {
		return nil, err
	}
	rule.ID, rule.ProjectID, rule.CreatedAt, rule.CreatedBy = old.ID, old.ProjectID, old.CreatedAt, old.CreatedBy
	nv := ruleValues(rule)
	nv["op"] = "update"
	e := AuditEntry{OrgID: t.OrgID, UserID: a.UserID, Action: ActionProtectionChange, ResourceType: ResourceProtection, ResourceID: rule.ID, IP: a.IP,
		OldValues: ruleValues(*old), NewValues: nv}
	if err := s.store.UpdateRule(ctx, &rule, e); err != nil {
		if errors.Is(err, ErrDuplicate) {
			return nil, &ConflictError{Code: "DUPLICATE_PATTERN", Message: "ya existe otra regla con el patrón «" + rule.Pattern + "»"}
		}
		return nil, err
	}
	syncs, _ := s.store.ListSync(ctx, t.ProjectID)
	st := syncs[rule.ID]
	st.RuleID, st.ProjectID = rule.ID, t.ProjectID
	if st.Status == "" {
		st.Status = SyncPending
	}
	if st.ForgejoRuleName != "" && st.ForgejoRuleName != rule.Pattern {
		st.StaleRuleNames = addUnique(st.StaleRuleNames, st.ForgejoRuleName)
		st.ForgejoRuleName = ""
	}
	if old.Pattern != rule.Pattern {
		// the old pattern may have been projected without us having recorded it: remove it too
		st.StaleRuleNames = addUnique(st.StaleRuleNames, old.Pattern)
	}
	s.project(ctx, t, rule, &st)

	after := make([]Rule, 0, len(before))
	for _, r := range before {
		if r.ID == rule.ID {
			r = rule
		}
		after = append(after, r)
	}
	if err := s.applyRepoEffects(ctx, t, after, a); err != nil {
		s.markError(ctx, &st, "ajustes del repositorio: "+describe(err))
	}
	warns = append(warns, s.defaultBranchWarnings(ctx, t, before, after)...)
	p := view(rule, &st, warns)
	return &p, nil
}

// Delete removes a rule. The Forgejo rule goes first: if Forgejo refuses, the Capsule rule stays
// (never claim a rule is gone while Forgejo still enforces it). It returns warnings (e.g. default
// branch left unprotected).
func (s *Service) Delete(ctx context.Context, t Target, a Actor, id uuid.UUID) ([]string, error) {
	defer s.lock(t.ProjectID)()
	old, err := s.store.GetRule(ctx, t.ProjectID, id)
	if err != nil {
		return nil, err
	}
	before, err := s.store.ListRules(ctx, t.ProjectID)
	if err != nil {
		return nil, err
	}
	syncs, _ := s.store.ListSync(ctx, t.ProjectID)
	st := syncs[id]

	names := addUnique(nil, old.Pattern)
	if st.ForgejoRuleName != "" {
		names = addUnique(names, st.ForgejoRuleName)
	}
	for _, n := range st.StaleRuleNames {
		names = addUnique(names, n)
	}
	// do not remove a name another rule of this project owns
	owned := map[string]bool{}
	for _, r := range before {
		if r.ID != id {
			owned[r.Pattern] = true
		}
	}
	if s.forge.Enabled() {
		for _, n := range names {
			if owned[n] {
				continue
			}
			if err := s.forge.DeleteProtection(ctx, s.ref(t), n); err != nil && !errors.Is(err, gitcore.ErrNotFound) {
				return nil, err
			}
		}
	} else if st.Status == SyncSynced {
		return nil, &gitcore.Error{Code: gitcore.CodeNotReady, Message: "la integración con Git no está activa: no se puede quitar la regla de Forgejo", Retry: true}
	}
	e := AuditEntry{OrgID: t.OrgID, UserID: a.UserID, Action: ActionProtectionChange, ResourceType: ResourceProtection, ResourceID: id, IP: a.IP,
		OldValues: ruleValues(*old), NewValues: map[string]any{"op": "delete", "pattern": old.Pattern}}
	if err := s.store.DeleteRule(ctx, t.ProjectID, id, e); err != nil {
		return nil, err
	}
	after := make([]Rule, 0, len(before))
	for _, r := range before {
		if r.ID != id {
			after = append(after, r)
		}
	}
	return s.defaultBranchWarnings(ctx, t, before, after), nil
}

// project writes the desired state of one rule to Forgejo and records the outcome in st.
func (s *Service) project(ctx context.Context, t Target, rule Rule, st *SyncState) {
	st.RuleID, st.ProjectID = rule.ID, t.ProjectID
	if !s.forge.Enabled() {
		st.Status, st.LastError = SyncPending, "GIT_NOT_READY: la integración con Git no está activa; se aplicará cuando lo esté"
		s.putSync(ctx, st)
		return
	}
	spec := BuildSpec(rule, t.ProjectSlug)
	if _, err := s.forge.UpsertProtection(ctx, s.ref(t), spec); err != nil {
		s.markError(ctx, st, describe(err))
		return
	}
	var left []string
	var lastErr string
	owned := map[string]bool{rule.Pattern: true}
	if len(st.StaleRuleNames) > 0 {
		if rs, err := s.store.ListRules(bg(ctx), t.ProjectID); err == nil {
			for _, r := range rs {
				owned[r.Pattern] = true
			}
		}
	}
	for _, n := range st.StaleRuleNames {
		if owned[n] {
			continue // another rule of the project owns that name now: it is not stale
		}
		if err := s.forge.DeleteProtection(ctx, s.ref(t), n); err != nil && !errors.Is(err, gitcore.ErrNotFound) {
			left = append(left, n)
			lastErr = describe(err)
		}
	}
	st.StaleRuleNames = left
	st.ForgejoRuleName = rule.Pattern
	st.SpecHash = SpecHash(spec)
	if len(left) > 0 {
		s.markError(ctx, st, "no se pudo quitar la regla anterior de Forgejo: "+lastErr)
		return
	}
	now := s.now()
	st.Status, st.LastError, st.Attempts, st.LastSyncedAt = SyncSynced, "", 0, &now
	s.putSync(ctx, st)
}

func (s *Service) markError(ctx context.Context, st *SyncState, msg string) {
	st.Status, st.LastError = SyncError, msg
	st.Attempts++
	s.putSync(ctx, st)
}

func (s *Service) putSync(ctx context.Context, st *SyncState) {
	st.UpdatedAt = s.now()
	if err := s.store.PutSync(bg(ctx), *st); err != nil {
		s.log.Error("gitprotect: saving sync state failed", "rule", st.RuleID, "err", err)
	}
}

func addUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// ---- repository-wide effects ---------------------------------------------------------------

var linearStyles = []string{"rebase", "fast-forward"}

func inSet(set []string, v string) bool {
	for _, x := range set {
		if x == v {
			return true
		}
	}
	return false
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		if !inSet(b, x) {
			return false
		}
	}
	return true
}

// applyRepoEffects projects the options Forgejo only has per repository: linear history
// (restricts the allowed merge styles to rebase/fast-forward) and delete-branch-on-merge.
// It never relaxes anything: removing the last linear rule leaves the restricted styles in
// place (the previous set is in the audit entry) until an admin changes them via repoUpdate.
func (s *Service) applyRepoEffects(ctx context.Context, t Target, rules []Rule, a Actor) error {
	var linear, del bool
	for _, r := range rules {
		linear = linear || r.RequireLinearHistory
		del = del || r.DeleteBranchOnMerge
	}
	if (!linear && !del) || !s.forge.Enabled() {
		return nil
	}
	repo, err := s.forge.GetRepo(ctx, s.ref(t))
	if err != nil {
		return err
	}
	var patch gitcore.RepoPatch
	changed := false
	newStyles := repo.AllowedMergeStyles
	if linear {
		var allowed []string
		for _, st := range repo.AllowedMergeStyles {
			if inSet(linearStyles, st) {
				allowed = append(allowed, st)
			}
		}
		if len(allowed) == 0 {
			allowed = append([]string{}, linearStyles...)
		}
		if !sameSet(allowed, repo.AllowedMergeStyles) {
			patch.AllowedMergeStyles = allowed
			newStyles = allowed
			changed = true
		}
	}
	if del && !repo.DeleteBranchOnPR {
		v := true
		patch.DeleteBranchOnPR = &v
		changed = true
	}
	if !changed {
		return nil
	}
	if _, err := s.forge.PatchRepo(ctx, s.ref(t), patch); err != nil {
		return err
	}
	s.audit(ctx, AuditEntry{OrgID: t.OrgID, UserID: a.UserID, Action: ActionRepoSettings, ResourceType: ResourceRepo, ResourceID: t.ProjectID, IP: a.IP,
		OldValues: map[string]any{"allowed_merge_styles": repo.AllowedMergeStyles, "delete_branch_on_merge": repo.DeleteBranchOnPR},
		NewValues: map[string]any{"allowed_merge_styles": newStyles, "delete_branch_on_merge": repo.DeleteBranchOnPR || del, "reason": "branch protection rules"}})
	return nil
}

// ---- warnings ------------------------------------------------------------------------------

var knownContexts = map[string]bool{CtxPreview: true, CtxSecurity: true, CtxPolicy: true}

// KnownContexts lists the fixed capsule/* contexts (capsule/env:<name> is open-ended).
func KnownContexts() []string { return []string{CtxPolicy, CtxPreview, CtxSecurity} }

func unknownContextWarnings(r Rule) []string {
	var w []string
	for _, c := range r.RequiredChecks {
		if strings.HasPrefix(c, "capsule/") && !knownContexts[c] && !strings.HasPrefix(c, CtxEnvPref) {
			w = append(w, "UNKNOWN_CAPSULE_CONTEXT: «"+c+"» no es un contexto que Capsule publique (capsule/preview, capsule/security, capsule/policy, capsule/env:<nombre>); si nadie lo publica, el merge quedará bloqueado")
		}
	}
	return w
}

// defaultBranchWarnings warns when the change leaves the default branch without any rule.
func (s *Service) defaultBranchWarnings(ctx context.Context, t Target, before, after []Rule) []string {
	if !s.forge.Enabled() {
		return nil
	}
	repo, err := s.forge.GetRepo(ctx, s.ref(t))
	if err != nil || repo.DefaultBranch == "" {
		return nil
	}
	if len(Rank(before, repo.DefaultBranch)) > 0 && len(Rank(after, repo.DefaultBranch)) == 0 {
		return []string{"DEFAULT_BRANCH_UNPROTECTED: la rama por defecto «" + repo.DefaultBranch + "» queda sin ninguna regla de protección; si el proyecto despliega a producción desde ella, cualquiera con escritura podrá empujar directamente"}
	}
	return nil
}

// ---- evaluate ------------------------------------------------------------------------------

// Match is one rule that matches the evaluated branch.
type Match struct {
	RuleID  uuid.UUID `json:"rule_id"`
	Pattern string    `json:"pattern"`
	Glob    bool      `json:"glob"`
	Applies bool      `json:"applies"`
	Why     string    `json:"why"`
}

// ForgejoView says what Forgejo itself would apply to the branch.
type ForgejoView struct {
	Rule   string   `json:"rule,omitempty"`
	InSync bool     `json:"in_sync"`
	Fields []string `json:"differing_fields,omitempty"`
	Note   string   `json:"note,omitempty"`
}

// Evaluation answers protectionEvaluate.
type Evaluation struct {
	Branch       string       `json:"branch"`
	Rule         *Protection  `json:"rule"`
	Reason       string       `json:"reason"`
	Requirements []string     `json:"requirements,omitempty"`
	Matches      []Match      `json:"matches,omitempty"`
	Forgejo      *ForgejoView `json:"forgejo,omitempty"`
}

// ValidBranchName reports whether name can be evaluated.
func ValidBranchName(name string) bool { return gitsource.ValidBranch(name) }

// Evaluate explains which rule applies to branch and why, and checks it against what Forgejo has.
func (s *Service) Evaluate(ctx context.Context, t Target, branch string) (*Evaluation, error) {
	if !ValidBranchName(branch) {
		return nil, &ValidationError{Fields: []FieldError{{Field: "branch", Message: "nombre de rama inválido"}}}
	}
	rules, err := s.store.ListRules(ctx, t.ProjectID)
	if err != nil {
		return nil, err
	}
	syncs, err := s.store.ListSync(ctx, t.ProjectID)
	if err != nil {
		return nil, err
	}
	ev := &Evaluation{Branch: branch}
	ranked := Rank(rules, branch)
	if len(ranked) == 0 {
		ev.Reason = "Ninguna regla coincide con «" + branch + "»: la rama no está protegida (se puede empujar, forzar y borrar según los permisos de escritura)."
	} else {
		w := ranked[0]
		var stp *SyncState
		if st, ok := syncs[w.Rule.ID]; ok {
			stp = &st
		}
		p := view(w.Rule, stp, nil)
		ev.Rule = &p
		ev.Requirements = Describe(w.Rule)
		ev.Reason = winnerReason(w, ranked)
		for i, m := range ranked {
			ev.Matches = append(ev.Matches, Match{RuleID: m.Rule.ID, Pattern: m.Rule.Pattern, Glob: !m.Plain, Applies: i == 0, Why: matchWhy(i, m, ranked)})
		}
	}
	ev.Forgejo = s.forgejoView(ctx, t, ev)
	return ev, nil
}

func winnerReason(w Ranked, all []Ranked) string {
	var b strings.Builder
	if w.Plain {
		b.WriteString("Se aplica la regla «" + w.Rule.Pattern + "»: coincide exactamente (sin glob) y las reglas sin glob tienen prioridad sobre las que tienen glob.")
	} else {
		b.WriteString("Se aplica la regla «" + w.Rule.Pattern + "»: coincide por glob (el asterisco simple no cruza la barra, el doble sí).")
		globs := 0
		for _, m := range all {
			if !m.Plain {
				globs++
			}
		}
		if globs > 1 {
			b.WriteString(" Hay varias reglas con glob que coinciden; gana la más antigua.")
		}
	}
	if len(all) > 1 {
		b.WriteString(" Solo se aplica una regla por rama: las demás coincidencias se ignoran, no se combinan.")
	}
	return b.String()
}

func matchWhy(i int, m Ranked, all []Ranked) string {
	if i == 0 {
		if m.Plain {
			return "gana: nombre exacto, sin glob"
		}
		return "gana: es la regla con glob más antigua que coincide"
	}
	if all[0].Plain && !m.Plain {
		return "descartada: tiene glob y ya coincide una regla sin glob («" + all[0].Rule.Pattern + "»)"
	}
	return "descartada: otra regla de la misma clase es más antigua («" + all[0].Rule.Pattern + "»)"
}

// Describe lists, in plain Spanish, what a rule enforces.
func Describe(r Rule) []string {
	var out []string
	switch {
	case !r.RequirePullRequest:
		out = append(out, "Push directo permitido a quien tenga escritura")
	case len(r.PushAllowRoles) > 0:
		out = append(out, "Push directo bloqueado salvo para: "+strings.Join(r.PushAllowRoles, ", "))
	default:
		out = append(out, "Push directo bloqueado: los cambios entran por pull request")
	}
	out = append(out, "Force-push y borrado de la rama bloqueados")
	if r.RequiredApprovals > 0 {
		out = append(out, fmt.Sprintf("%d aprobación(es) necesaria(s)", r.RequiredApprovals))
	}
	if r.DismissStaleApprovals {
		out = append(out, "Las aprobaciones se descartan al llegar commits nuevos")
	}
	if r.BlockOnRejectedReviews {
		out = append(out, "Una revisión que pide cambios bloquea el merge")
	}
	if r.RequireCodeOwnerReview {
		out = append(out, "Revisión de CODEOWNERS obligatoria")
	}
	if c := RequiredContexts(r); len(c) > 0 {
		out = append(out, "Checks obligatorios: "+strings.Join(c, ", "))
	}
	if r.RequireUpToDate {
		out = append(out, "La rama debe estar al día con la base")
	}
	if r.RequireSignedCommits {
		out = append(out, "Commits firmados obligatorios")
	}
	if r.RequireLinearHistory {
		out = append(out, "Historial lineal: solo rebase y fast-forward en el repositorio")
	}
	if len(r.MergeAllowRoles) > 0 {
		out = append(out, "Pueden fusionar: "+strings.Join(r.MergeAllowRoles, ", "))
	}
	if r.EnforceForAdmins {
		out = append(out, "También rige para administradores")
	} else {
		out = append(out, "Los administradores del repositorio en Forgejo quedan exentos")
	}
	return out
}

func (s *Service) forgejoView(ctx context.Context, t Target, ev *Evaluation) *ForgejoView {
	if !s.forge.Enabled() {
		return &ForgejoView{Note: "la integración con Git no está activa; no se pudo comparar con Forgejo"}
	}
	fp, err := s.forge.ListProtections(ctx, s.ref(t))
	if err != nil {
		return &ForgejoView{Note: "no se pudo consultar Forgejo: " + describe(err)}
	}
	var fr []Rule
	for _, p := range fp {
		fr = append(fr, Rule{ID: uuid.NewSHA1(uuid.NameSpaceURL, []byte(p.RuleName)), Pattern: p.RuleName, CreatedAt: p.CreatedAt})
	}
	rk := Rank(fr, ev.Branch)
	fv := &ForgejoView{}
	if len(rk) > 0 {
		fv.Rule = rk[0].Rule.Pattern
	}
	switch {
	case ev.Rule == nil && fv.Rule == "":
		fv.InSync = true
	case ev.Rule == nil:
		fv.Note = "Forgejo aplica la regla «" + fv.Rule + "», que Capsule no conoce"
	case fv.Rule != ev.Rule.Pattern:
		fv.Note = "Forgejo aplicaría «" + fv.Rule + "» en lugar de «" + ev.Rule.Pattern + "»; la reconciliación lo corrige"
	default:
		for i := range fp {
			if fp[i].RuleName == fv.Rule {
				fv.Fields = DiffSpec(BuildSpec(ev.Rule.Rule, t.ProjectSlug), fp[i].ProtectionSpec)
			}
		}
		fv.InSync = len(fv.Fields) == 0
		if !fv.InSync {
			fv.Note = "la regla en Forgejo difiere de la de Capsule; la reconciliación la corrige"
		}
	}
	return fv
}
