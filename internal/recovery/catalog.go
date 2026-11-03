package recovery

import (
	"context"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/backup"
)

// ProjectInfo is what the catalog needs about a project besides its backups.
type ProjectInfo struct {
	ID       uuid.UUID
	Slug     string
	GitReady bool
}

// Source is the database side of the catalog (repository.RecoveryRepository implements it).
type Source interface {
	Projects(ctx context.Context) ([]ProjectInfo, error)
	Snapshots(ctx context.Context) ([]backup.Snapshot, error) // every non-deleted snapshot, project or platform
}

func refOf(s backup.Snapshot) SnapshotRef {
	return SnapshotRef{ID: s.ID, ProjectID: s.ProjectID, Kind: s.Kind, Source: s.Source, SourceID: s.SourceID,
		Engine: s.Engine, ObjectKey: s.ObjectKey, Size: s.SizeBytes, Checksum: s.Checksum, CreatedAt: s.CreatedAt.UTC()}
}

// LoadCatalog reads the catalog from the database and verifies the NEWEST manifest of each project
// (it does not fall back to an older one when the newest is rejected: a tampered object must show).
// forgejo may be nil (no Git dumps listed).
func LoadCatalog(ctx context.Context, src Source, v *Verifier, forgejo backup.Store, now time.Time) (Catalog, error) {
	projects, err := src.Projects(ctx)
	if err != nil {
		return Catalog{}, err
	}
	snaps, err := src.Snapshots(ctx)
	if err != nil {
		return Catalog{}, err
	}
	cat := Catalog{Now: now.UTC(), Projects: []ProjectEntry{}, Platform: []SnapshotRef{}, ForgejoDumps: []DumpRef{}}
	byProject := map[uuid.UUID]*ProjectEntry{}
	for _, p := range projects {
		cat.Projects = append(cat.Projects, ProjectEntry{ID: p.ID, Slug: p.Slug, GitReady: p.GitReady, Snapshots: []SnapshotRef{}})
	}
	for i := range cat.Projects {
		byProject[cat.Projects[i].ID] = &cat.Projects[i]
	}
	for _, s := range snaps {
		if s.ProjectID == nil {
			if s.Kind == "platform" {
				cat.Platform = append(cat.Platform, refOf(s))
			}
			continue
		}
		if p := byProject[*s.ProjectID]; p != nil {
			p.Snapshots = append(p.Snapshots, refOf(s))
		}
	}
	for i := range cat.Projects {
		verifyNewestManifest(ctx, v, &cat.Projects[i])
	}
	if forgejo != nil {
		cat.ForgejoDumps, err = ListForgejoDumps(ctx, forgejo)
		if err != nil {
			return Catalog{}, err
		}
	}
	return cat, nil
}

func verifyNewestManifest(ctx context.Context, v *Verifier, p *ProjectEntry) {
	var newest *SnapshotRef
	for i := range p.Snapshots {
		s := &p.Snapshots[i]
		if s.Kind != "manifest" {
			continue
		}
		if newest == nil || s.CreatedAt.After(newest.CreatedAt) || (s.CreatedAt.Equal(newest.CreatedAt) && s.ID.String() > newest.ID.String()) {
			newest = s
		}
	}
	if newest == nil || v == nil {
		return
	}
	m, err := v.Manifest(ctx, *newest)
	if err != nil {
		p.ManifestErr = err.Error()
		return
	}
	p.Manifest = Summarize(*newest, m)
	if p.Slug == "" {
		p.Slug = m.Project.Slug
	}
}

// ListForgejoDumps lists forgejo/*.tar.gz.enc and reads each .sha256 sidecar.
func ListForgejoDumps(ctx context.Context, st backup.Store) ([]DumpRef, error) {
	objs, err := st.List(ctx, "forgejo/")
	if err != nil {
		return nil, err
	}
	has := map[string]bool{}
	for _, o := range objs {
		has[o.Key] = true
	}
	out := []DumpRef{}
	for _, o := range objs {
		if !strings.HasSuffix(o.Key, ".tar.gz.enc") {
			continue
		}
		d := DumpRef{Key: o.Key, Size: o.Size, LastModified: o.LastModified.UTC()}
		if has[o.Key+".sha256"] {
			if body, _, err := st.Download(ctx, o.Key+".sha256"); err == nil {
				b, _ := io.ReadAll(io.LimitReader(body, 4096))
				body.Close()
				if f := strings.Fields(string(b)); len(f) > 0 && len(f[0]) == 64 {
					d.Sha256 = strings.ToLower(f[0])
				}
			}
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

var bucketNS = uuid.MustParse("6f1d1a4e-9c1b-4e0e-8f7b-2f6a5c4d3b21")

// CatalogFromBucket builds the catalog from the bucket layout alone (bootstrap mode: the database
// does not exist yet). There are no stored checksums, so integrity relies on the GCM tags; the
// planner reports NO_CHECKSUM_CATALOG. Slugs come from the verified manifests.
func CatalogFromBucket(ctx context.Context, st backup.Store, v *Verifier, forgejo backup.Store, now time.Time) (Catalog, error) {
	objs, err := st.List(ctx, "")
	if err != nil {
		return Catalog{}, err
	}
	cat := Catalog{Now: now.UTC(), FromBucket: true, Projects: []ProjectEntry{}, Platform: []SnapshotRef{}, ForgejoDumps: []DumpRef{}}
	by := map[uuid.UUID][]SnapshotRef{}
	for _, o := range objs {
		ref, ok := refFromKey(o)
		if !ok {
			continue
		}
		if ref.ProjectID == nil {
			cat.Platform = append(cat.Platform, ref)
			continue
		}
		by[*ref.ProjectID] = append(by[*ref.ProjectID], ref)
	}
	ids := make([]string, 0, len(by))
	for id := range by {
		ids = append(ids, id.String())
	}
	sort.Strings(ids)
	for _, s := range ids {
		id := uuid.MustParse(s)
		cat.Projects = append(cat.Projects, ProjectEntry{ID: id, Snapshots: by[id]})
	}
	for i := range cat.Projects {
		verifyNewestManifest(ctx, v, &cat.Projects[i])
	}
	if forgejo != nil {
		if cat.ForgejoDumps, err = ListForgejoDumps(ctx, forgejo); err != nil {
			return Catalog{}, err
		}
	}
	return cat, nil
}

// refFromKey parses projects/<pid>/<kind>/<ts>-<run>.<ext>.enc and platform/<ts>-<run>.<part>.<ext>.enc.
func refFromKey(o backup.ObjectInfo) (SnapshotRef, bool) {
	if !strings.HasSuffix(o.Key, ".enc") || strings.HasSuffix(o.Key, ".meta.json") {
		return SnapshotRef{}, false
	}
	parts := strings.Split(o.Key, "/")
	ref := SnapshotRef{ID: uuid.NewSHA1(bucketNS, []byte(o.Key)), ObjectKey: o.Key, Size: o.Size}
	var name string
	switch {
	case len(parts) == 4 && parts[0] == "projects":
		pid, err := uuid.Parse(parts[1])
		if err != nil {
			return SnapshotRef{}, false
		}
		ref.ProjectID, ref.Kind, name = &pid, parts[2], parts[3]
	case len(parts) == 2 && parts[0] == "platform":
		ref.Kind, name = "platform", parts[1]
	default:
		return SnapshotRef{}, false
	}
	stem, rest, ok := strings.Cut(name, ".")
	if !ok || len(stem) < 38 {
		return SnapshotRef{}, false
	}
	ts, err := time.Parse(time.RFC3339, stem[:len(stem)-37])
	if err != nil {
		return SnapshotRef{}, false
	}
	ref.CreatedAt = ts.UTC()
	rest = strings.TrimSuffix(rest, ".enc")
	switch ref.Kind {
	case "platform":
		ref.Source, _, _ = strings.Cut(rest, ".") // files | inventory
	case "database":
		id, ext, _ := strings.Cut(rest, ".")
		ref.Source, ref.SourceID, ref.Engine = id, id, ext
	case "volume":
		ref.Source = "capsule-data-" + parts[1]
	case "manifest":
		ref.Source = "manifest"
	default:
		return SnapshotRef{}, false
	}
	return ref, true
}
