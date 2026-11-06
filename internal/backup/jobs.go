package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/pkg/crypto"
)

// putStream encrypts src (envelope) and uploads it to key without ever holding the whole
// dump in memory or on disk. If src's process fails, the upload is aborted: nothing is stored.
func (s *Service) putStream(ctx context.Context, key string, src io.ReadCloser) (stored int64, sum string, err error) {
	dek, err := NewDEK()
	if err != nil {
		src.Close()
		return 0, "", err
	}
	wrapped, err := WrapDEK(dek, s.secret)
	if err != nil {
		src.Close()
		return 0, "", err
	}
	meta := map[string]string{metaDEK: wrapped, metaVer: metaEnc}
	pr, pw := io.Pipe()
	h := sha256.New()
	done := make(chan struct{})
	go func() {
		defer close(done)
		ew, werr := NewEncryptWriter(pw, dek)
		if werr != nil {
			src.Close()
			pw.CloseWithError(werr)
			return
		}
		_, cerr := io.Copy(io.MultiWriter(ew, h), src)
		if xerr := src.Close(); cerr == nil { // exit status of the dump process
			cerr = xerr
		}
		if cerr == nil {
			cerr = ew.Close()
		}
		pw.CloseWithError(cerr) // nil => EOF
	}()
	stored, err = s.store.Upload(ctx, key, meta, pr)
	pr.CloseWithError(errors.New("upload finished"))
	<-done
	if err != nil {
		return 0, "", err
	}
	return stored, hex.EncodeToString(h.Sum(nil)), nil
}

func (s *Service) putBytes(ctx context.Context, key string, data []byte) (int64, string, error) {
	return s.putStream(ctx, key, io.NopCloser(bytes.NewReader(data)))
}

func (s *Service) record(ctx context.Context, rs *runState, run Run, kind, source, sourceID, engineName, key string, stored int64, sum string, data bool) error {
	sn := &Snapshot{ID: uuid.New(), ProjectID: run.ProjectID, RunID: run.ID, Kind: kind, Source: source, SourceID: sourceID,
		Engine: engineName, ObjectKey: key, SizeBytes: stored, Checksum: sum, CreatedAt: s.now().UTC()}
	if err := s.repo.AddSnapshot(ctx, sn); err != nil {
		return fmt.Errorf("recording snapshot %s: %w", source, err)
	}
	rs.size += stored
	if data {
		rs.data++
	}
	return nil
}

// ── project backup ──────────────────────────────────────────────────────────

func (s *Service) projectOnce(ctx context.Context, run Run, st Settings, rs *runState) []string {
	var errs []string
	pid := *run.ProjectID
	proj, err := s.project(ctx, pid)
	if err != nil {
		return []string{"loading project: " + err.Error()}
	}
	dbs, err := s.dbs.ListByProject(ctx, pid)
	if err != nil {
		return []string{"listing databases: " + err.Error()}
	}
	if !rs.done["manifest"] {
		if err := s.backupManifest(ctx, rs, run, proj, dbs); err != nil {
			errs = append(errs, "manifest: "+err.Error())
		} else {
			rs.done["manifest"] = true
		}
	}
	if st.IncludeDatabases {
		for _, d := range dbs {
			if d.Status != "available" || rs.done["db:"+d.ID.String()] {
				continue
			}
			if err := s.backupDatabase(ctx, rs, run, d); err != nil {
				errs = append(errs, fmt.Sprintf("database %q: %v", d.Name, err))
			}
		}
	}
	if st.IncludeVolumes && !rs.done["volume"] {
		if err := s.backupVolume(ctx, rs, run); err != nil {
			errs = append(errs, "volume: "+err.Error())
		}
	}
	if st.IncludeVolumes && s.objects != nil && !rs.done["objects"] {
		if err := s.backupObjects(ctx, rs, run); err != nil {
			errs = append(errs, "objects: "+err.Error())
		}
	}
	if len(errs) == 0 && st.IncludeDatabases && rs.data == 0 && len(rs.notes) > 0 && !st.IncludeVolumes {
		return []string{"nothing was backed up: " + strings.Join(rs.notes, "; ")}
	}
	return errs
}

type dbCreds struct{ Username, Password string }

func (s *Service) creds(d *domain.Database) (dbCreds, error) {
	if len(d.CredentialsEnc) == 0 {
		return dbCreds{}, errors.New("no stored credentials")
	}
	plain, err := crypto.Decrypt(d.CredentialsEnc, s.secret)
	if err != nil {
		return dbCreds{}, errors.New("cannot decrypt stored credentials")
	}
	var c struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(plain, &c); err != nil {
		return dbCreds{}, errors.New("cannot parse stored credentials")
	}
	return dbCreds{c.Username, c.Password}, nil
}

func (s *Service) target(d *domain.Database) (DBTarget, error) {
	c, err := s.creds(d)
	if err != nil {
		return DBTarget{}, err
	}
	return DBTarget{Container: dbContainerName(d.ID), Engine: d.Engine, DBName: d.DBName, User: c.Username, Password: c.Password}, nil
}

func (s *Service) backupDatabase(ctx context.Context, rs *runState, run Run, d *domain.Database) error {
	key := "db:" + d.ID.String()
	eng, err := engineFor(d.Engine)
	if err != nil {
		rs.notes = append(rs.notes, fmt.Sprintf("skipped database %q: %v", d.Name, err))
		rs.done[key] = true
		return nil
	}
	if _, err := inspectContainer(ctx, s.dock, dbContainerName(d.ID)); err != nil {
		rs.notes = append(rs.notes, fmt.Sprintf("skipped database %q: not a container on this host (managed externally)", d.Name))
		rs.done[key] = true
		return nil
	}
	t, err := s.target(d)
	if err != nil {
		return err
	}
	src, err := s.dock.Stream(ctx, eng.dump(t))
	if err != nil {
		return fmt.Errorf("starting dump: %w", err)
	}
	objKey := ObjectKey(*run.ProjectID, "database", run.StartedAt, run.ID, d.ID.String()[:8]+"."+eng.ext)
	stored, sum, err := s.putStream(ctx, objKey, src)
	if err != nil {
		return err
	}
	if err := s.record(ctx, rs, run, "database", d.Name, d.ID.String(), d.Engine, objKey, stored, sum, true); err != nil {
		return err
	}
	rs.done[key] = true
	return nil
}

// volumeBackupScript runs in the ephemeral helper with the data volume mounted read-only.
// SQLite files are taken with `sqlite3 .backup` (consistent) when the helper image has
// sqlite3; otherwise (or if the backup fails) they are copied as they are.
const volumeBackupScript = `set -eu
cd /data
: > /tmp/skip.list
if command -v sqlite3 >/dev/null 2>&1; then
  find . -type f \( -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' \) | while IFS= read -r f; do
    if [ "$(head -c 15 "$f" 2>/dev/null)" = "SQLite format 3" ]; then
      mkdir -p "/snap/$(dirname "$f")"
      if sqlite3 -readonly "$f" ".backup '/snap/$f'" 2>/dev/null; then echo "$f" >> /tmp/skip.list
      else echo "warning: sqlite3 .backup of $f failed, copied as is" >&2; rm -f "/snap/$f"; fi
    fi
  done
fi
exec tar --numeric-owner -czf - -X /tmp/skip.list -C /data . -C /snap .`

func (s *Service) volumeExists(ctx context.Context, name string) bool {
	_, err := s.dock.Run(ctx, Cmd{Args: []string{"volume", "inspect", name}})
	return err == nil
}

func (s *Service) backupVolume(ctx context.Context, rs *runState, run Run) error {
	vol := dataVolumeName(*run.ProjectID)
	if !s.volumeExists(ctx, vol) {
		rs.done["volume"] = true
		return nil
	}
	src, err := s.dock.Stream(ctx, Cmd{Args: []string{"run", "--rm", "--network", "none", "--read-only",
		"--memory", "512m", "--cpus", "1", "--pids-limit", "256",
		"--tmpfs", "/snap:rw,size=1g", "--tmpfs", "/tmp:rw,size=64m",
		"-v", vol + ":/data:ro", s.cfg.HelperImage, "sh", "-c", volumeBackupScript}})
	if err != nil {
		return fmt.Errorf("starting helper: %w", err)
	}
	objKey := ObjectKey(*run.ProjectID, "volume", run.StartedAt, run.ID, "tar.gz")
	stored, sum, err := s.putStream(ctx, objKey, src)
	if err != nil {
		return err
	}
	if err := s.record(ctx, rs, run, "volume", vol, "", "", objKey, stored, sum, true); err != nil {
		return err
	}
	rs.done["volume"] = true
	return nil
}

func (s *Service) backupManifest(ctx context.Context, rs *runState, run Run, proj *domain.Project, dbs []*domain.Database) error {
	m, err := s.buildManifest(ctx, run, proj, dbs)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	key := ObjectKey(proj.ID, "manifest", run.StartedAt, run.ID, "json")
	stored, sum, err := s.putBytes(ctx, key, data)
	if err != nil {
		return err
	}
	return s.record(ctx, rs, run, "manifest", "manifest", "", "", key, stored, sum, false)
}

func (s *Service) buildManifest(ctx context.Context, run Run, proj *domain.Project, dbs []*domain.Database) (*Manifest, error) {
	in, err := s.repo.LastDeployment(ctx, proj.ID)
	if err != nil {
		return nil, fmt.Errorf("loading last deployment: %w", err)
	}
	m := &Manifest{Schema: ManifestSchema, GeneratedAt: s.now().UTC(), RunID: run.ID,
		Project: ManifestProject{ID: proj.ID, OrgID: proj.OrgID, Slug: proj.Slug, Runtime: proj.Runtime, DeployType: proj.DeployType},
		Volumes: []ManifestVolume{}, EnvVarNames: []string{}, Databases: []ManifestDatabase{}}
	if proj.HealthPath != nil {
		m.Project.HealthPath = *proj.HealthPath
	}
	if in != nil {
		if in.EnvVarNames != nil {
			m.EnvVarNames = in.EnvVarNames
		}
		if in.DeploymentID != uuid.Nil {
			m.Deployment = &ManifestDeploy{ID: in.DeploymentID, Version: in.Version, GitSHA: in.GitSHA, ImageTag: in.ImageTag,
				SourceKey: in.SourceKey, ContainerPort: in.ContainerPort, HostPort: in.HostPort}
			if in.DeployType != "" {
				m.Project.DeployType = in.DeployType
			}
		}
	}
	app := appContainerName(proj.ID)
	if m.Deployment != nil {
		if out, err := s.dock.Run(ctx, Cmd{Args: []string{"image", "inspect", app}}); err == nil {
			var imgs []struct {
				ID          string   `json:"Id"`
				RepoDigests []string `json:"RepoDigests"`
			}
			if json.Unmarshal(out, &imgs) == nil && len(imgs) > 0 {
				m.Deployment.ImageID, m.Deployment.ImageDigests = imgs[0].ID, imgs[0].RepoDigests
			}
		}
	}
	if doc, err := inspectContainer(ctx, s.dock, app); err == nil {
		c := &ManifestContainer{Name: app, Image: doc.Config.Image, RestartPolicy: doc.HostConfig.RestartPolicy.Name,
			Networks: doc.networks(), MemoryBytes: doc.HostConfig.Memory, NanoCPUs: doc.HostConfig.NanoCpus, Ports: doc.ports()}
		if doc.Config.Healthcheck != nil {
			c.HealthTest = doc.Config.Healthcheck.Test
		}
		m.Container = c
		m.Volumes = doc.volumes()
	} else if s.volumeExists(ctx, dataVolumeName(proj.ID)) {
		m.Volumes = []ManifestVolume{{Name: dataVolumeName(proj.ID), MountPoint: "/data"}}
	}
	for _, d := range dbs {
		md := ManifestDatabase{ID: d.ID, Name: d.Name, Engine: d.Engine, Version: d.Version, DBName: d.DBName,
			HostPort: d.Port, Container: dbContainerName(d.ID), Volumes: []ManifestVolume{}}
		if doc, err := inspectContainer(ctx, s.dock, md.Container); err == nil {
			md.Present, md.Image, md.Volumes, md.RestartPolicy = true, doc.Config.Image, doc.volumes(), doc.HostConfig.RestartPolicy.Name
		}
		m.Databases = append(m.Databases, md)
	}
	return m, nil
}

// ── platform backup ─────────────────────────────────────────────────────────

// Inventory is the platform inventory (schema 1): what runs on the host, no secret values.
type Inventory struct {
	Schema      int                  `json:"schema"`
	GeneratedAt time.Time            `json:"generated_at"`
	RunID       uuid.UUID            `json:"run_id"`
	Volumes     []string             `json:"volumes"`
	PS          []string             `json:"ps"`
	Containers  []InventoryContainer `json:"containers"`
}

type InventoryContainer struct {
	Name          string           `json:"name"`
	Image         string           `json:"image"`
	ImageID       string           `json:"image_id"`
	Status        string           `json:"status"`
	RestartPolicy string           `json:"restart_policy"`
	Networks      []string         `json:"networks"`
	Ports         []ManifestPort   `json:"published_ports"`
	Mounts        []InventoryMount `json:"mounts"`
	EnvNames      []string         `json:"env_names"`
	HealthTest    []string         `json:"health_test,omitempty"`
}

type InventoryMount struct {
	Type        string `json:"type"`
	Name        string `json:"name,omitempty"`
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination"`
}

func lines(b []byte) []string {
	out := []string{}
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func (s *Service) buildInventory(ctx context.Context, run Run) (*Inventory, error) {
	inv := &Inventory{Schema: ManifestSchema, GeneratedAt: s.now().UTC(), RunID: run.ID, Containers: []InventoryContainer{}}
	vols, err := s.dock.Run(ctx, Cmd{Args: []string{"volume", "ls", "--format", "{{.Name}}"}})
	if err != nil {
		return nil, fmt.Errorf("docker volume ls: %w", err)
	}
	inv.Volumes = lines(vols)
	ps, err := s.dock.Run(ctx, Cmd{Args: []string{"ps", "-a", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"}})
	if err != nil {
		return nil, fmt.Errorf("docker ps: %w", err)
	}
	inv.PS = lines(ps)
	ids, err := s.dock.Run(ctx, Cmd{Args: []string{"ps", "-a", "-q"}})
	if err != nil {
		return nil, fmt.Errorf("docker ps -q: %w", err)
	}
	if list := lines(ids); len(list) > 0 {
		out, err := s.dock.Run(ctx, Cmd{Args: append([]string{"inspect"}, list...)})
		if err != nil {
			return nil, fmt.Errorf("docker inspect: %w", err)
		}
		var docs []inspectDoc
		if err := json.Unmarshal(out, &docs); err != nil {
			return nil, fmt.Errorf("parsing docker inspect: %w", err)
		}
		for _, d := range docs {
			c := InventoryContainer{Name: strings.TrimPrefix(d.Name, "/"), Image: d.Config.Image, ImageID: d.Image, Status: d.State.Status,
				RestartPolicy: d.HostConfig.RestartPolicy.Name, Networks: d.networks(), Ports: d.ports(),
				Mounts: []InventoryMount{}, EnvNames: envNames(d.Config.Env)}
			if d.Config.Healthcheck != nil {
				c.HealthTest = d.Config.Healthcheck.Test
			}
			for _, m := range d.Mounts {
				c.Mounts = append(c.Mounts, InventoryMount{Type: m.Type, Name: m.Name, Source: m.Source, Destination: m.Destination})
			}
			inv.Containers = append(inv.Containers, c)
		}
	}
	return inv, nil
}

// platformFilesScript runs in an ephemeral helper that sees ONLY the platform dir and the docker
// config dir, both read-only, with no network. The tarball is encrypted before it leaves this process.
const platformFilesScript = `set -eu
cd /host
set --
for f in capsule/docker-compose*.yml capsule/.env capsule/certs docker/daemon.json; do
  [ -e "$f" ] && set -- "$@" "$f"
done
[ "$#" -gt 0 ] || { echo "no platform files found" >&2; exit 3; }
exec tar --numeric-owner -czf - "$@"`

func (s *Service) platformOnce(ctx context.Context, run Run, rs *runState) []string {
	var errs []string
	if !rs.done["files"] {
		src, err := s.dock.Stream(ctx, Cmd{Args: []string{"run", "--rm", "--network", "none", "--read-only",
			"--memory", "256m", "--pids-limit", "128",
			"-v", s.cfg.PlatformDir + ":/host/capsule:ro", "-v", s.cfg.DockerConfigDir + ":/host/docker:ro",
			s.cfg.HelperImage, "sh", "-c", platformFilesScript}})
		if err == nil {
			key := PlatformKey(run.StartedAt, run.ID, "files", "tar.gz")
			var stored int64
			var sum string
			if stored, sum, err = s.putStream(ctx, key, src); err == nil {
				if err = s.record(ctx, rs, run, "platform", "files", "", "", key, stored, sum, true); err == nil {
					rs.done["files"] = true
				}
			}
		}
		if err != nil {
			errs = append(errs, "platform files: "+err.Error())
		}
	}
	if !rs.done["inventory"] {
		inv, err := s.buildInventory(ctx, run)
		if err == nil {
			var data []byte
			if data, err = json.MarshalIndent(inv, "", "  "); err == nil {
				key := PlatformKey(run.StartedAt, run.ID, "inventory", "json")
				var stored int64
				var sum string
				if stored, sum, err = s.putBytes(ctx, key, data); err == nil {
					if err = s.record(ctx, rs, run, "platform", "inventory", "", "", key, stored, sum, false); err == nil {
						rs.done["inventory"] = true
					}
				}
			}
		}
		if err != nil {
			errs = append(errs, "inventory: "+err.Error())
		}
	}
	return errs
}

// ── verification ────────────────────────────────────────────────────────────

// checkSnapshot downloads, decrypts and hashes a snapshot; it never touches data.
func (s *Service) checkSnapshot(ctx context.Context, sn Snapshot, pipeTo io.Writer) (int64, error) {
	body, plain, err := openObject(ctx, s.store, s.secret, sn.ObjectKey)
	if err != nil {
		return 0, err
	}
	defer body.Close()
	h := sha256.New()
	w := io.Writer(h)
	if pipeTo != nil {
		w = io.MultiWriter(h, pipeTo)
	}
	n, err := io.Copy(w, plain)
	if err != nil {
		return n, err
	}
	if sn.Checksum != "" && hex.EncodeToString(h.Sum(nil)) != sn.Checksum {
		return n, errors.New("checksum mismatch")
	}
	return n, nil
}

// verify checks the latest snapshot of every source: decrypt + checksum, and for Postgres
// `pg_restore --list` on the dump. Results land in the run (status/error).
func (s *Service) verify(ctx context.Context, run Run) (int64, error) {
	all, err := s.repo.ListSnapshots(ctx, run.ProjectID)
	if err != nil {
		return 0, err
	}
	latest := map[string]Snapshot{}
	var order []string
	for _, sn := range all { // newest first
		k := sn.Kind + "|" + sn.Source
		if _, ok := latest[k]; !ok {
			latest[k] = sn
			order = append(order, k)
		}
	}
	if len(order) == 0 {
		return 0, errors.New("no backups to verify")
	}
	var total int64
	var errs []string
	for _, k := range order {
		sn := latest[k]
		n, err := s.verifyOne(ctx, sn)
		total += n
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s %q (%s): %v", sn.Kind, sn.Source, sn.CreatedAt.Format(time.RFC3339), err))
		}
	}
	if len(errs) > 0 {
		return total, errors.New(strings.Join(errs, "; "))
	}
	return total, nil
}

func (s *Service) verifyOne(ctx context.Context, sn Snapshot) (int64, error) {
	if sn.Kind == "database" && sn.Engine == "postgres" && sn.ProjectID != nil && sn.SourceID != "" {
		if id, err := uuid.Parse(sn.SourceID); err == nil {
			if _, ierr := inspectContainer(ctx, s.dock, dbContainerName(id)); ierr == nil {
				body, plain, err := openObject(ctx, s.store, s.secret, sn.ObjectKey)
				if err != nil {
					return 0, err
				}
				defer body.Close()
				h := sha256.New()
				cmd := *postgresEngine.list(DBTarget{Container: dbContainerName(id)})
				cmd.Stdin = io.TeeReader(plain, h)
				if out, err := s.dock.Run(ctx, cmd); err != nil {
					return 0, fmt.Errorf("pg_restore --list failed: %s", firstLine(out, err))
				}
				// pg_restore may stop reading early; drain so the checksum covers everything.
				n, err := io.Copy(h, plain)
				_ = n
				if err != nil {
					return 0, err
				}
				if sn.Checksum != "" && hex.EncodeToString(h.Sum(nil)) != sn.Checksum {
					return 0, errors.New("checksum mismatch")
				}
				return sn.SizeBytes, nil
			}
		}
	}
	_, err := s.checkSnapshot(ctx, sn, nil)
	return sn.SizeBytes, err
}

func firstLine(out []byte, err error) string {
	l := lines(out)
	if len(l) > 0 {
		return l[len(l)-1]
	}
	return err.Error()
}

// ── restore ─────────────────────────────────────────────────────────────────

func (s *Service) executeRestore(run Run, sn *Snapshot, target string) {
	ctx, cancel := context.WithTimeout(s.baseCtx, s.cfg.RunTimeout)
	defer cancel()
	if !s.acquire(ctx) {
		s.finish(run, 0, errors.New("cancelled before start"), nil)
		return
	}
	defer func() { <-s.sem }()
	s.audit(ctx, run, "backup.restore.start", map[string]any{"run_id": run.ID.String(), "snapshot_id": sn.ID.String(), "kind": sn.Kind, "source": sn.Source, "target": target})
	defer func() {
		if r := recover(); r != nil {
			s.finish(run, 0, fmt.Errorf("internal error: %v", r), nil)
		}
	}()
	// Integrity first: nothing is touched unless the whole snapshot decrypts and matches its checksum.
	if _, err := s.checkSnapshot(ctx, *sn, nil); err != nil {
		s.finish(run, 0, fmt.Errorf("snapshot failed verification, nothing was restored: %w", err), nil)
		return
	}
	var err error
	switch sn.Kind {
	case "database":
		err = s.restoreDatabase(ctx, sn, target)
	case "objects":
		err = s.restoreObjects(ctx, sn)
	default:
		err = s.restoreVolume(ctx, run, sn)
	}
	s.finish(run, sn.SizeBytes, err, nil)
}

func (s *Service) restoreDatabase(ctx context.Context, sn *Snapshot, target string) error {
	id, err := uuid.Parse(sn.SourceID)
	if err != nil || sn.ProjectID == nil {
		return errors.New("snapshot has no database reference")
	}
	dbs, err := s.dbs.ListByProject(ctx, *sn.ProjectID)
	if err != nil {
		return err
	}
	var d *domain.Database
	for _, x := range dbs {
		if x.ID == id {
			d = x
		}
	}
	if d == nil {
		return errors.New("the database of this snapshot no longer exists")
	}
	eng, err := engineFor(sn.Engine)
	if err != nil || eng.restore == nil {
		return fmt.Errorf("restore not supported for engine %q", sn.Engine)
	}
	t, err := s.target(d)
	if err != nil {
		return err
	}
	if target != "" && strings.EqualFold(target, d.DBName) {
		return errors.New("target must differ from the original database; omit it to restore in place")
	}
	created := false
	if target != "" && eng.create != nil {
		if out, err := s.dock.Run(ctx, eng.create(t, target)); err != nil {
			return fmt.Errorf("creating target database: %s", firstLine(out, err))
		}
		created = true
	}
	cmd, err := eng.restore(t, target)
	if err != nil {
		return err
	}
	body, plain, err := openObject(ctx, s.store, s.secret, sn.ObjectKey)
	if err != nil {
		return err
	}
	defer body.Close()
	cmd.Stdin = plain
	if out, err := s.dock.Run(ctx, cmd); err != nil {
		if target != "" && eng.drop != nil { // roll back the new database
			dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
			defer cancel()
			_, _ = s.dock.Run(dctx, eng.drop(t, target))
		}
		_ = created
		return fmt.Errorf("restore failed (in-place restores of postgres roll back automatically): %s", firstLine(out, err))
	}
	return nil
}

const (
	volumeExtractScript = `set -eu; mkdir -p /stage/new; exec tar --numeric-owner -xzpf - -C /stage/new`
	volumeSwapScript    = `set -eu
mkdir -p /stage/old
find /data -mindepth 1 -maxdepth 1 -exec mv {} /stage/old/ \;
find /stage/new -mindepth 1 -maxdepth 1 -exec mv {} /data/ \;`
	volumeRollbackScript = `set -eu
find /data -mindepth 1 -maxdepth 1 -exec rm -rf {} +
find /stage/old -mindepth 1 -maxdepth 1 -exec mv {} /data/ \;`
)

// restoreVolume extracts into a staging volume first (the live data is untouched until the
// archive is fully extracted), then stops the project's containers, swaps the contents keeping
// the previous data in staging, and restarts. Any failure rolls the previous data back.
func (s *Service) restoreVolume(ctx context.Context, run Run, sn *Snapshot) (err error) {
	vol := sn.Source
	if sn.ProjectID == nil || vol != dataVolumeName(*sn.ProjectID) {
		return errors.New("snapshot does not reference this project's data volume")
	}
	stage := "capsule-restore-" + run.ID.String()
	bg := context.WithoutCancel(ctx)
	helper := func(c context.Context, stdin io.Reader, script string, mounts ...string) ([]byte, error) {
		args := []string{"run", "--rm", "-i", "--network", "none", "--memory", "512m", "--pids-limit", "256"}
		args = append(args, mounts...)
		args = append(args, s.cfg.HelperImage, "sh", "-c", script)
		return s.dock.Run(c, Cmd{Args: args, Stdin: stdin})
	}
	if out, e := s.dock.Run(ctx, Cmd{Args: []string{"volume", "create", stage}}); e != nil {
		return fmt.Errorf("creating staging volume: %s", firstLine(out, e))
	}
	keepStage := false // true when the staging volume holds the only copy of the previous data
	defer func() {
		if !keepStage {
			_, _ = s.dock.Run(bg, Cmd{Args: []string{"volume", "rm", "-f", stage}})
		}
	}()

	body, plain, e := openObject(ctx, s.store, s.secret, sn.ObjectKey)
	if e != nil {
		return e
	}
	defer body.Close()
	if out, e := helper(ctx, plain, volumeExtractScript, "-v", stage+":/stage"); e != nil {
		return fmt.Errorf("extracting archive (live data untouched): %s", firstLine(out, e))
	}

	// containers currently using the volume
	psOut, _ := s.dock.Run(ctx, Cmd{Args: []string{"ps", "--filter", "volume=" + vol, "--format", "{{.Names}}"}})
	running := lines(psOut)
	restart := func() error {
		if len(running) == 0 {
			return nil
		}
		if out, e := s.dock.Run(bg, Cmd{Args: append([]string{"start"}, running...)}); e != nil {
			return fmt.Errorf("restarting containers: %s", firstLine(out, e))
		}
		return nil
	}
	if len(running) > 0 {
		if out, e := s.dock.Run(ctx, Cmd{Args: append([]string{"stop"}, running...)}); e != nil {
			_ = restart()
			return fmt.Errorf("stopping containers: %s", firstLine(out, e))
		}
	}
	mounts := []string{"-v", vol + ":/data", "-v", stage + ":/stage"}
	if out, e := helper(ctx, nil, volumeSwapScript, mounts...); e != nil {
		rbErr := ""
		if rout, re := helper(bg, nil, volumeRollbackScript, mounts...); re != nil {
			rbErr = "; ROLLBACK FAILED, previous data is preserved in volume " + stage + ": " + firstLine(rout, re)
			keepStage = true
		}
		_ = restart()
		return fmt.Errorf("swapping data failed, previous data restored: %s%s", firstLine(out, e), rbErr)
	}
	if e := restart(); e != nil {
		return e
	}
	return nil
}
