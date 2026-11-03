package recovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Thresholds of the risk rules (DR-BACKUP.md sections 8 and 11, action 5).
const (
	staleDataAfter  = 48 * time.Hour // newest data backup of a project older than this is a risk
	staleDumpAfter  = 26 * time.Hour // Forgejo: alert when no dump in the last 26 h
	bytesPerSecond  = 20 << 20       // restore throughput used for estimates (hypothesis until a real drill)
	fixedProjectSec = 600            // image rebuild + container start per project (hypothesis)
)

// BuildPlan turns a request and a catalog into the plan. It is deterministic and does no I/O: the
// same (request, catalog) yields byte-identical JSON, including PlanID. Selection rules:
//   - per (kind, source) the newest snapshot not after `At` (or newest overall), ties by ID;
//   - `SnapshotID` pins the chosen snapshot of its own source (project recovery only);
//   - phases in the order of DR-BACKUP.md section 4.
func BuildPlan(req Request, cat Catalog) (Plan, error) {
	req, err := req.Normalize()
	if err != nil {
		return Plan{}, err
	}
	projects := append([]ProjectEntry(nil), cat.Projects...)
	sort.Slice(projects, func(i, j int) bool { return projects[i].ID.String() < projects[j].ID.String() })
	if !req.All {
		var one []ProjectEntry
		for _, p := range projects {
			if p.ID == *req.ProjectID {
				one = append(one, p)
			}
		}
		if len(one) == 0 {
			return Plan{}, fmt.Errorf("%w: project %s is not in the catalog", ErrNotFound, req.ProjectID)
		}
		projects = one
	}
	if req.SnapshotID != nil && !pinnedExists(projects, *req.SnapshotID) {
		return Plan{}, fmt.Errorf("%w: snapshot %s does not belong to the project", ErrNotFound, req.SnapshotID)
	}

	b := &planner{req: req, cat: cat}
	b.add(Step{ID: "f0-preflight", Phase: "F0", Kind: KindPreflight, Name: "F0 preflight: credentials, encryption key, tools, backup checksums", EstimateSec: 30})

	coreID := ""
	if req.All {
		if req.hasScope(ScopeNetwork) {
			name := "F1 network: terraform plan/apply (VPC, SG, elastic IP, buckets, IAM)"
			if req.Target == TargetEphemeral {
				name = "F1 network: isolated drill instance (deploy/terraform/recovery_drill.tf)"
			}
			b.add(Step{ID: "f1-network", Phase: "F1", Kind: KindNetwork, Name: name, NeedsInfraFlag: true,
				DependsOn: []string{"f0-preflight"}, EstimateSec: 2400})
		}
		if req.hasScope(ScopeCore) {
			b.core(cat)
			coreID = "f2-core"
		}
		if req.hasScope(ScopeGit) {
			b.git(cat, coreID)
		}
	}

	hasProject := req.hasScope(ScopeDatabases) || req.hasScope(ScopeVolumes) || req.hasScope(ScopeProjects)
	if hasProject {
		for _, p := range projects {
			b.project(p, coreID)
		}
	}
	if req.All && req.hasScope(ScopeDNS) {
		dep := []string{"f0-preflight"}
		if coreID != "" {
			dep = append(dep, coreID)
		}
		b.add(Step{ID: "f7-dns", Phase: "F7", Kind: KindDNS, Name: "F7 DNS and certificates: same elastic IP or list of records to change", DependsOn: dep, EstimateSec: 300})
	}
	b.add(Step{ID: "f8-smoke", Phase: "F8", Kind: KindSmoke, Name: "F8 global verification: health, counts, sample git fsck, restore test", EstimateSec: 300})
	b.add(Step{ID: "f9-report", Phase: "F9", Kind: KindReport, Name: "F9 report: what came from which backup, durations, estimated RPO", EstimateSec: 10})

	sortRisks(b.risks)
	p := Plan{Request: req, Steps: b.steps, Risks: b.risks}
	if p.Risks == nil {
		p.Risks = []Risk{}
	}
	for _, s := range p.Steps {
		p.EstimateSecond += s.EstimateSec
	}
	p.Ready = len(p.Blockers()) == 0
	raw, err := json.Marshal(p)
	if err != nil {
		return Plan{}, err
	}
	sum := sha256.Sum256(raw)
	p.PlanID = hex.EncodeToString(sum[:])
	return p, nil
}

func pinnedExists(ps []ProjectEntry, id uuid.UUID) bool {
	for _, p := range ps {
		for _, s := range p.Snapshots {
			if s.ID == id {
				return true
			}
		}
	}
	return false
}

type planner struct {
	req   Request
	cat   Catalog
	steps []Step
	risks []Risk
}

func (b *planner) add(s Step)  { b.steps = append(b.steps, s) }
func (b *planner) risk(r Risk) { b.risks = append(b.risks, r) }

// pick chooses the newest snapshot of each (kind, source, source_id) group of snaps.
func (b *planner) pick(snaps []SnapshotRef, kind string) []SnapshotRef {
	groups := map[string][]SnapshotRef{}
	for _, s := range snaps {
		if s.Kind != kind {
			continue
		}
		if b.req.At != nil && s.CreatedAt.After(*b.req.At) {
			continue
		}
		k := s.Source + "\x00" + s.SourceID
		groups[k] = append(groups[k], s)
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []SnapshotRef
	for _, k := range keys {
		g := groups[k]
		sort.Slice(g, func(i, j int) bool {
			if !g[i].CreatedAt.Equal(g[j].CreatedAt) {
				return g[i].CreatedAt.After(g[j].CreatedAt)
			}
			return g[i].ID.String() > g[j].ID.String()
		})
		chosen := g[0]
		if b.req.SnapshotID != nil {
			for _, s := range g {
				if s.ID == *b.req.SnapshotID {
					chosen = s
				}
			}
		}
		chosen.CreatedAt = chosen.CreatedAt.UTC()
		out = append(out, chosen)
	}
	return out
}

func (b *planner) core(cat Catalog) {
	b.add(Step{ID: "f2-core", Phase: "F2", Kind: KindCore, Name: "F2 core: restore RDS (PITR or snapshot) to a new instance, start host, backend, redis, frontend",
		Destructive: true, NeedsInfraFlag: true, DependsOn: coreDeps(b.req), EstimateSec: 3000})
	files := b.pick(cat.Platform, "platform")
	var chosen *SnapshotRef
	for i := range files {
		if files[i].Source == "files" {
			chosen = &files[i]
		}
	}
	if chosen == nil {
		b.risk(Risk{Code: "NO_PLATFORM_BACKUP", Severity: "error", Subject: "platform",
			Message: "no platform files backup (compose, .env, certificates, platform keys): F2 cannot decrypt secrets"})
		return
	}
	b.add(Step{ID: "f2-platform-files", Phase: "F2", Kind: KindPlatform, Name: "F2 platform files: compose, .env, certificates, platform keys (encrypted backup)",
		Snapshot: chosen, Destructive: true, DependsOn: []string{"f2-core"}, EstimateSec: 120 + int(chosen.Size/bytesPerSecond)})
	if age := cat.Now.Sub(chosen.CreatedAt); !cat.Now.IsZero() && age > staleDataAfter {
		b.risk(Risk{Code: "STALE_BACKUP", Severity: "warning", Subject: "platform",
			Message: fmt.Sprintf("newest platform backup is %s old", age.Truncate(time.Hour))})
	}
}

func coreDeps(req Request) []string {
	if req.hasScope(ScopeNetwork) {
		return []string{"f1-network"}
	}
	return []string{"f0-preflight"}
}

func (b *planner) git(cat Catalog, coreID string) {
	dumps := append([]DumpRef(nil), cat.ForgejoDumps...)
	var cand []DumpRef
	for _, d := range dumps {
		if b.req.At != nil && d.LastModified.After(*b.req.At) {
			continue
		}
		cand = append(cand, d)
	}
	sort.Slice(cand, func(i, j int) bool {
		if !cand[i].LastModified.Equal(cand[j].LastModified) {
			return cand[i].LastModified.After(cand[j].LastModified)
		}
		return cand[i].Key > cand[j].Key
	})
	if len(cand) == 0 {
		b.risk(Risk{Code: "NO_FORGEJO_DUMP", Severity: "error", Subject: "git", Message: "no forgejo dump available for the requested point in time"})
		return
	}
	d := cand[0]
	d.LastModified = d.LastModified.UTC()
	dep := []string{"f0-preflight"}
	if coreID != "" {
		dep = []string{coreID}
	}
	if d.Sha256 == "" {
		b.risk(Risk{Code: "DUMP_NO_CHECKSUM", Severity: "error", Subject: d.Key, Message: "forgejo dump has no .sha256 sidecar: integrity cannot be verified"})
	}
	if age := cat.Now.Sub(d.LastModified); !cat.Now.IsZero() && age > staleDumpAfter {
		b.risk(Risk{Code: "STALE_FORGEJO_DUMP", Severity: "warning", Subject: d.Key,
			Message: fmt.Sprintf("newest forgejo dump is %s old (objective: at most 6 h, alert at 26 h)", age.Truncate(time.Hour))})
	}
	b.add(Step{ID: "f3-git", Phase: "F3", Kind: KindGit, Name: "F3 git: forgejo dump -> volume, regenerate hooks, doctor, Caddy state, runner token",
		Dump: &d, Destructive: true, DependsOn: dep, EstimateSec: 1800 + int(d.Size/bytesPerSecond)})
}

func (b *planner) project(p ProjectEntry, coreID string) {
	label := p.Slug
	if label == "" {
		label = p.ID.String()
	}
	pid := p.ID
	if len(p.Snapshots) == 0 {
		b.risk(Risk{Code: "NO_BACKUP", Severity: "error", Subject: label, ProjectID: &pid, Message: "project has no backups at all"})
		return
	}
	if p.ManifestErr != "" {
		b.risk(Risk{Code: "MANIFEST_INVALID", Severity: "error", Subject: label, ProjectID: &pid,
			Message: "manifest rejected, the project is excluded from the plan: " + p.ManifestErr})
		return
	}
	if p.Manifest == nil && b.req.hasScope(ScopeProjects) {
		b.risk(Risk{Code: "NO_MANIFEST", Severity: "error", Subject: label, ProjectID: &pid,
			Message: "no manifest: containers cannot be re-created (data can still be restored)"})
	}
	dbs := b.pick(p.Snapshots, "database")
	vols := b.pick(p.Snapshots, "volume")
	dep := []string{"f0-preflight"}
	if coreID != "" {
		dep = []string{coreID}
	}
	var projDeps []string
	if b.req.hasScope(ScopeDatabases) {
		for _, s := range dbs {
			s := s
			id := "f4-db-" + s.ID.String()
			b.add(Step{ID: id, Phase: "F4", Kind: KindDatabase, ProjectID: &pid, Snapshot: &s, DependsOn: dep, Destructive: true,
				ContinueOnError: true, EstimateSec: 60 + int(s.Size/bytesPerSecond),
				Name: fmt.Sprintf("F4 database %s (%s) of %s", s.Source, s.Engine, label)})
			projDeps = append(projDeps, id)
		}
	}
	if b.req.hasScope(ScopeVolumes) {
		for _, s := range vols {
			s := s
			id := "f5-vol-" + s.ID.String()
			b.add(Step{ID: id, Phase: "F5", Kind: KindVolume, ProjectID: &pid, Snapshot: &s, DependsOn: dep, Destructive: true,
				ContinueOnError: true, EstimateSec: 30 + int(s.Size/bytesPerSecond),
				Name: fmt.Sprintf("F5 volume %s of %s", s.Source, label)})
			projDeps = append(projDeps, id)
		}
	}
	if m := p.Manifest; m != nil {
		for _, dbID := range m.Databases {
			if !hasSource(dbs, "SourceID", dbID) {
				b.risk(Risk{Code: "NO_DB_BACKUP", Severity: "error", Subject: label + "/" + dbID, ProjectID: &pid,
					Message: "the manifest lists database " + dbID + " but no database backup exists for it"})
			}
		}
		for _, v := range m.Volumes {
			if !hasSource(vols, "Source", v) {
				b.risk(Risk{Code: "NO_VOLUME_BACKUP", Severity: "warning", Subject: label + "/" + v, ProjectID: &pid,
					Message: "project without volume backup: files uploaded by users will be lost (include_volumes is off)"})
			}
		}
		if !m.HasSource {
			b.risk(Risk{Code: "NO_SOURCE_ARCHIVE", Severity: "warning", Subject: label, ProjectID: &pid,
				Message: "the manifest has neither a source archive nor image digests: the image may not be rebuildable"})
		}
	}
	if b.req.hasScope(ScopeProjects) && p.Manifest != nil {
		mid := p.Manifest.SnapshotID
		var msnap *SnapshotRef
		for i := range p.Snapshots {
			if p.Snapshots[i].ID == mid {
				c := p.Snapshots[i]
				c.CreatedAt = c.CreatedAt.UTC()
				msnap = &c
			}
		}
		b.add(Step{ID: "f6-project-" + pid.String(), Phase: "F6", Kind: KindProject, ProjectID: &pid, Snapshot: msnap,
			DependsOn: append(append([]string(nil), dep...), projDeps...), ContinueOnError: true, EstimateSec: fixedProjectSec,
			Name: "F6 project " + label + ": rebuild image, re-create containers from the manifest, ports, health"})
	}
	// freshness of the newest data backup
	if !b.cat.Now.IsZero() {
		var newest time.Time
		for _, s := range append(append([]SnapshotRef(nil), dbs...), vols...) {
			if s.CreatedAt.After(newest) {
				newest = s.CreatedAt
			}
		}
		if !newest.IsZero() && b.cat.Now.Sub(newest) > staleDataAfter {
			b.risk(Risk{Code: "STALE_BACKUP", Severity: "warning", Subject: label, ProjectID: &pid,
				Message: fmt.Sprintf("newest data backup is %s old", b.cat.Now.Sub(newest).Truncate(time.Hour))})
		}
	}
	if b.cat.FromBucket {
		b.risk(Risk{Code: "NO_CHECKSUM_CATALOG", Severity: "warning", Subject: label, ProjectID: &pid,
			Message: "catalog built from the bucket listing: integrity relies on the AES-GCM tags, not on stored checksums"})
	}
}

func hasSource(snaps []SnapshotRef, field, want string) bool {
	for _, s := range snaps {
		v := s.Source
		if field == "SourceID" {
			v = s.SourceID
		}
		if strings.EqualFold(v, want) {
			return true
		}
		// bucket-derived catalogs only know the 8-char id prefix of the key
		if field == "SourceID" && len(v) == 8 && strings.HasPrefix(strings.ToLower(want), strings.ToLower(v)) {
			return true
		}
	}
	return false
}
