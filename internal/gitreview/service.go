package gitreview

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/gitapi"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitevents"
)

// Config tunes the worker. ConfigFromEnv reads GITREVIEW_*.
type Config struct {
	SweepEvery  time.Duration // periodic retry of armed rows (default 60 s)
	Lease       time.Duration // a merge attempt holds the row this long (default 2 min)
	MaxAttempts int           // failed merge attempts before auto-merge is cancelled (default 20)
	MaxAge      time.Duration // an armed row older than this is cancelled (default 7 days)
	CacheTTL    time.Duration // CODEOWNERS and roster cache (default 20 s)
}

func (c Config) withDefaults() Config {
	if c.SweepEvery <= 0 {
		c.SweepEvery = time.Minute
	}
	if c.Lease <= 0 {
		c.Lease = 2 * time.Minute
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 20
	}
	if c.MaxAge <= 0 {
		c.MaxAge = 7 * 24 * time.Hour
	}
	if c.CacheTTL <= 0 {
		c.CacheTTL = 20 * time.Second
	}
	return c
}

// ConfigFromEnv reads GITREVIEW_SWEEP_SECONDS, GITREVIEW_LEASE_SECONDS, GITREVIEW_MAX_ATTEMPTS.
func ConfigFromEnv() Config {
	var c Config
	if n, _ := strconv.Atoi(strings.TrimSpace(os.Getenv("GITREVIEW_SWEEP_SECONDS"))); n > 0 {
		c.SweepEvery = time.Duration(n) * time.Second
	}
	if n, _ := strconv.Atoi(strings.TrimSpace(os.Getenv("GITREVIEW_LEASE_SECONDS"))); n > 0 {
		c.Lease = time.Duration(n) * time.Second
	}
	if n, _ := strconv.Atoi(strings.TrimSpace(os.Getenv("GITREVIEW_MAX_ATTEMPTS"))); n > 0 {
		c.MaxAttempts = n
	}
	return c.withDefaults()
}

// Service is the whole B8 logic. Core, Projects, Roster and Store are required.
type Service struct {
	Core       gitcore.Core
	Projects   Projects
	Roster     Roster
	Store      AutoMergeStore
	Authz      Authorizer          // nil = the role of the requester is not re-checked
	Dismissals DismissalLog        // nil = dismissals are not recorded in Capsule
	Publisher  gitevents.Publisher // nil = gitevents.Shared()
	Cfg        Config
	Log        *slog.Logger
	Now        func() time.Time

	mu     sync.Mutex
	owners map[string]cached[*File]
	roster map[uuid.UUID]cached[[]Member]
}

type cached[T any] struct {
	v  T
	at time.Time
}

// New builds a Service with defaults.
func New(core gitcore.Core, projects Projects, roster Roster, store AutoMergeStore, cfg Config, log *slog.Logger) *Service {
	return &Service{Core: core, Projects: projects, Roster: roster, Store: store, Cfg: cfg.withDefaults(), Log: log,
		owners: map[string]cached[*File]{}, roster: map[uuid.UUID]cached[[]Member]{}}
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Service) cfg() Config { return s.Cfg.withDefaults() }

func (s *Service) publisher() gitevents.Publisher {
	if s.Publisher != nil {
		return s.Publisher
	}
	return gitevents.Shared()
}

// members returns the project roster, cached for a few seconds.
func (s *Service) members(ctx context.Context, p Project) ([]Member, error) {
	s.mu.Lock()
	c, ok := s.roster[p.ID]
	s.mu.Unlock()
	if ok && s.now().Sub(c.at) < s.cfg().CacheTTL {
		return c.v, nil
	}
	ms, err := s.Roster.Members(ctx, p)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.roster == nil {
		s.roster = map[uuid.UUID]cached[[]Member]{}
	}
	s.roster[p.ID] = cached[[]Member]{ms, s.now()}
	s.mu.Unlock()
	return ms, nil
}

// LoadCodeowners reads the CODEOWNERS of ref (a branch; "" = default branch). nil, nil when the
// repository has none.
func (s *Service) LoadCodeowners(ctx context.Context, p Project, ref string) (*File, error) {
	if ref == "" {
		repo, err := s.Core.GetRepo(ctx, p.Ref)
		if err != nil {
			return nil, err
		}
		ref = repo.DefaultBranch
	}
	key := p.Ref.String() + "@" + ref
	s.mu.Lock()
	c, ok := s.owners[key]
	s.mu.Unlock()
	if ok && s.now().Sub(c.at) < s.cfg().CacheTTL {
		return c.v, nil
	}
	var found *File
	for _, path := range OwnersFiles {
		b, err := s.Core.GetFile(ctx, p.Ref, ref, path)
		if err != nil {
			if errors.Is(err, gitcore.ErrNotFound) {
				continue
			}
			return nil, err
		}
		if b.Truncated {
			found = &File{Path: path, Warnings: []string{"CODEOWNERS supera 1 MiB y no se lee"}}
			break
		}
		content := b.Content
		if b.Encoding == "base64" {
			return nil, fmt.Errorf("gitreview: %s is binary", path)
		}
		found = Parse(path, []byte(content))
		break
	}
	s.mu.Lock()
	if s.owners == nil {
		s.owners = map[string]cached[*File]{}
	}
	s.owners[key] = cached[*File]{found, s.now()}
	s.mu.Unlock()
	return found, nil
}

// OwnerView is one rule of codeownersGet.
type OwnerView struct {
	Pattern       string      `json:"pattern"`
	Owners        []string    `json:"owners"`
	ResolvedUsers []PersonOut `json:"resolved_users"`
	Negative      bool        `json:"negative"`
}

// PersonOut is the API Person schema.
type PersonOut struct {
	UserID *uuid.UUID `json:"user_id"`
	Login  string     `json:"login"`
	Name   string     `json:"name"`
	Email  string     `json:"email"`
}

// CodeownersDoc is the API Codeowners schema.
type CodeownersDoc struct {
	Path     string      `json:"path"`
	Rules    []OwnerView `json:"rules"`
	Warnings []string    `json:"warnings"`
}

// CodeownersView returns the CODEOWNERS of ref resolved to Capsule users.
func (s *Service) CodeownersView(ctx context.Context, p Project, ref string) (*CodeownersDoc, error) {
	f, err := s.LoadCodeowners(ctx, p, ref)
	if err != nil {
		return nil, err
	}
	doc := &CodeownersDoc{Rules: []OwnerView{}, Warnings: []string{}}
	if f == nil {
		return doc, nil
	}
	doc.Path = f.Path
	doc.Warnings = append(doc.Warnings, f.Warnings...)
	roster, err := s.members(ctx, p)
	if err != nil {
		return nil, err
	}
	var all []string
	for _, r := range f.Rules {
		all = append(all, r.Owners...)
	}
	res := ResolveOwners(all, p, roster)
	warned := map[string]bool{}
	for _, r := range f.Rules {
		v := OwnerView{Pattern: r.Pattern, Owners: r.Owners, ResolvedUsers: []PersonOut{}, Negative: r.Negative}
		seen := map[uuid.UUID]bool{}
		for _, o := range r.Owners {
			ref := res[o]
			if ref.Status != OwnerOK && !warned[o] {
				warned[o] = true
				doc.Warnings = append(doc.Warnings, fmt.Sprintf("linea %d: %s no se resuelve a un usuario con permiso de revision (%s)", r.Line, o, ref.Status))
			}
			for _, m := range ref.Users {
				if !seen[m.UserID] {
					seen[m.UserID] = true
					id := m.UserID
					v.ResolvedUsers = append(v.ResolvedUsers, PersonOut{UserID: &id, Login: m.Login, Email: m.Email})
				}
			}
		}
		doc.Rules = append(doc.Rules, v)
	}
	return doc, nil
}

// rule returns the protection rule that applies to the base branch (nil = none).
func (s *Service) rule(ctx context.Context, ref gitcore.RepoRef, base string) (*gitcore.ProtectionSpec, error) {
	rules, err := s.Core.ListProtections(ctx, ref)
	if err != nil {
		return nil, err
	}
	return gitapi.MatchRule(rules, base), nil
}

// PullStatus computes required and pending reviews of a pull request, code owners included when
// the rule requires them.
func (s *Service) PullStatus(ctx context.Context, p Project, pr gitcore.Pull) (*Status, error) {
	rule, err := s.rule(ctx, p.Ref, pr.Base)
	if err != nil {
		return nil, err
	}
	return s.statusWithRule(ctx, p, pr, rule)
}

func (s *Service) statusWithRule(ctx context.Context, p Project, pr gitcore.Pull, rule *gitcore.ProtectionSpec) (*Status, error) {
	reviews, err := s.Core.ListReviews(ctx, p.Ref, pr.Number)
	if err != nil {
		return nil, err
	}
	in := StatusInput{Pull: pr, Reviews: reviews, Rule: rule}
	if rule != nil && rule.BlockOnOfficialReviewRequest {
		f, err := s.LoadCodeowners(ctx, p, pr.Base)
		if err != nil {
			return nil, err
		}
		if f != nil {
			d, err := s.Core.PullDiff(ctx, p.Ref, pr.Number)
			if err != nil {
				return nil, err
			}
			for _, fd := range d.Files {
				in.Files = append(in.Files, fd.Path)
				if fd.OldPath != "" {
					in.Files = append(in.Files, fd.OldPath)
				}
			}
			roster, err := s.members(ctx, p)
			if err != nil {
				return nil, err
			}
			var raw []string
			for _, r := range f.Rules {
				raw = append(raw, r.Owners...)
			}
			in.Owners, in.Resolved = f, ResolveOwners(raw, p, roster)
		}
	}
	st := ComputeStatus(in)
	return &st, nil
}

// BlockerSource is for gitapi.RegisterBlockerSource: CODEOWNER_REQUIRED while a required code owner
// group has no qualifying approval. Errors make the PR unmergeable (fail closed, done by gitapi).
func (s *Service) BlockerSource(ctx context.Context, ref gitcore.RepoRef, pr gitcore.Pull) ([]gitapi.Blocker, error) {
	if pr.State != gitcore.PullOpen {
		return nil, nil
	}
	rule, err := s.rule(ctx, ref, pr.Base)
	if err != nil || rule == nil || !rule.BlockOnOfficialReviewRequest {
		return nil, err
	}
	p, err := s.Projects.ByRef(ctx, ref)
	if err != nil {
		return nil, err
	}
	st, err := s.statusWithRule(ctx, *p, pr, rule)
	if err != nil {
		return nil, err
	}
	if !st.Unsatisfied() {
		return nil, nil
	}
	msg := "waiting for approval from code owners"
	if len(st.CodeOwnerPending) > 0 {
		msg += ": @" + strings.Join(st.CodeOwnerPending, ", @")
	} else {
		msg += ": no other code owner is available to approve"
	}
	return []gitapi.Blocker{{Code: gitapi.BlockCodeowner, Message: msg}}, nil
}

// CodeownersPending is for gitapi.RegisterCodeownerSource.
func (s *Service) CodeownersPending(ctx context.Context, ref gitcore.RepoRef, pr gitcore.Pull) ([]string, error) {
	p, err := s.Projects.ByRef(ctx, ref)
	if err != nil {
		return nil, err
	}
	st, err := s.PullStatus(ctx, *p, pr)
	if err != nil {
		return nil, err
	}
	return st.CodeOwnerPending, nil
}

// PolicyState is what capsule/policy says about a pull request right now.
func PolicyState(pr gitcore.Pull, st *Status) (gitcore.CheckState, string) {
	if pr.Draft {
		return gitcore.CheckPending, "Borrador: marca el PR como listo para revision"
	}
	if st != nil && st.CodeOwnerRequired && st.Unsatisfied() {
		if len(st.CodeOwnerPending) > 0 {
			return gitcore.CheckPending, "Falta la aprobacion de propietarios de codigo: @" + strings.Join(st.CodeOwnerPending, ", @")
		}
		return gitcore.CheckPending, "Falta la aprobacion de propietarios de codigo"
	}
	return gitcore.CheckSuccess, "Politica de revision cumplida"
}

// RefreshPolicy publishes capsule/policy on the PR head when its state changed. Failures to
// evaluate leave the previous check alone (it is never turned green by an error).
func (s *Service) RefreshPolicy(ctx context.Context, p Project, pr gitcore.Pull) error {
	if pr.State != gitcore.PullOpen || pr.HeadSHA == "" {
		return nil
	}
	rule, err := s.rule(ctx, p.Ref, pr.Base)
	if err != nil {
		return err
	}
	var st *Status
	if rule != nil && rule.BlockOnOfficialReviewRequest && !pr.Draft {
		if st, err = s.statusWithRule(ctx, p, pr, rule); err != nil {
			return err
		}
	}
	state, desc := PolicyState(pr, st)
	if cur, err := s.Core.ListChecks(ctx, p.Ref, pr.HeadSHA); err == nil {
		for _, c := range cur.Items {
			if c.Context == PolicyContext && c.State == state && c.Description == desc {
				return nil
			}
		}
	}
	_, err = s.Core.SetCheck(ctx, p.Ref, pr.HeadSHA, gitcore.CheckInput{Context: PolicyContext, State: state, Description: desc})
	return err
}

func actorOf(ctx context.Context, login string) context.Context { return gitcore.WithActor(ctx, login) }

var _ = authz.GitMerge
