package service

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Scheduled, safe cleanup of the docker build cache and orphan images.
//
// Safety rules (see TestCleanup*):
//   - never touches an image used by ANY container (running or stopped);
//   - never touches the image of a project that has a successful deployment
//     (that image IS the last successful deployment) while the project exists;
//   - skips the orphan-image step entirely while a deployment is building or
//     deploying (its freshly built image has no container yet);
//   - plain `docker rmi` (no -f), so docker itself refuses to remove in-use images;
//   - dangling images and build cache older than CacheMaxAge are pruned; when the
//     disk is above DiskMaxPercent the cache is cut down to a small floor.
//
// Disk alert: a warning is logged when usage is at or above 80%.

const (
	protectedProjectsSQL = `
		SELECT DISTINCT substr(replace(d.project_id::text, '-', ''), 1, 12)
		FROM deployments d JOIN projects p ON p.id = d.project_id
		WHERE d.status = 'success' AND p.deleted_at IS NULL`
	activeDeploymentsSQL = `SELECT COUNT(*) FROM deployments WHERE status IN ('building','deploying')`
)

var (
	appImageRe = regexp.MustCompile(`^capsule-app-([0-9a-f]{12})$`)
	dfPctRe    = regexp.MustCompile(`(\d+)%`)
)

// CleanupReport summarizes one cleanup pass (also logged).
type CleanupReport struct {
	DiskPercent    int
	Aggressive     bool
	RemovedImages  []string
	SkippedActive  bool
	ProtectedCount int
}

// RunCleanupLoop runs cleanupOnce every CleanupInterval until ctx is done.
// CleanupInterval == 0 disables the loop.
func (w *DeployWorker) RunCleanupLoop(ctx context.Context) {
	w.ext.init()
	iv := w.ext.cfg.CleanupInterval
	if iv <= 0 {
		w.logger.Info("docker cleanup loop disabled (CAPSULE_CLEANUP_INTERVAL_HOURS=0)")
		return
	}
	// First pass shortly after start so a full disk is noticed early.
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Minute):
	}
	for {
		w.CleanupOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(iv):
		}
	}
}

// CleanupOnce runs one cleanup pass. Best effort: errors are logged, never fatal.
func (w *DeployWorker) CleanupOnce(ctx context.Context) CleanupReport {
	w.ext.init()
	cfg := w.ext.cfg
	rep := CleanupReport{}

	pct, err := w.diskPercent(ctx, cfg.DiskPath)
	if err != nil {
		w.logger.Warn("docker cleanup: could not read disk usage", "path", cfg.DiskPath, "error", err)
	} else {
		rep.DiskPercent = pct
		if pct >= cfg.DiskWarnPercent {
			w.logger.Warn("DISK ALERT: usage above 80% on the docker host", "path", cfg.DiskPath, "used_percent", pct, "max_percent", cfg.DiskMaxPercent)
		}
		rep.Aggressive = pct >= cfg.DiskMaxPercent
	}

	// 1. dangling images (never in use by definition).
	_, _ = w.ext.docker(ctx, dockerCall{Args: []string{"image", "prune", "-f"}})

	// 2. build cache: age threshold + size floor.
	keep := cfg.CacheKeepStorage
	args := []string{"builder", "prune", "-f"}
	if rep.Aggressive {
		keep = "1GB"
		w.logger.Warn("docker cleanup: disk above limit, pruning build cache aggressively", "keep_storage", keep)
	} else if cfg.CacheMaxAge > 0 {
		args = append(args, "--filter", fmt.Sprintf("until=%dh", int(cfg.CacheMaxAge.Hours())))
	}
	if keep != "" {
		args = append(args, "--keep-storage", keep)
	}
	if out, err := w.ext.docker(ctx, dockerCall{Args: args}); err != nil {
		w.logger.Warn("docker cleanup: builder prune failed", "error", strings.TrimSpace(string(out)))
	}

	// 3. orphan images.
	removed, skipped, nprot := w.removeOrphanImages(ctx)
	rep.RemovedImages, rep.SkippedActive, rep.ProtectedCount = removed, skipped, nprot

	w.logger.Info("docker cleanup finished", "disk_percent", rep.DiskPercent, "aggressive", rep.Aggressive,
		"removed_images", len(removed), "skipped_orphan_step", skipped)
	return rep
}

func (w *DeployWorker) diskPercent(ctx context.Context, path string) (int, error) {
	if w.ext.diskUsage != nil {
		return w.ext.diskUsage(ctx, path)
	}
	out, err := exec.CommandContext(ctx, "df", "-P", path).Output()
	if err != nil {
		return 0, err
	}
	return parseDfPercent(string(out))
}

// parseDfPercent extracts the Capacity column of `df -P`.
func parseDfPercent(out string) (int, error) {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 2 {
		return 0, fmt.Errorf("unexpected df output")
	}
	m := dfPctRe.FindStringSubmatch(lines[len(lines)-1])
	if m == nil {
		return 0, fmt.Errorf("no percentage in df output")
	}
	return strconv.Atoi(m[1])
}

type imageRow struct{ Repo, Tag, ID string }

func parseImages(out string) []imageRow {
	var rows []imageRow
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		p := strings.Split(strings.TrimSpace(line), "|")
		if len(p) == 3 && p[0] != "" && p[0] != "<none>" {
			rows = append(rows, imageRow{p[0], p[1], p[2]})
		}
	}
	return rows
}

// removeOrphanImages deletes capsule app images that no container uses and that
// are not the last successful deployment of an existing project.
func (w *DeployWorker) removeOrphanImages(ctx context.Context) (removed []string, skipped bool, protectedCount int) {
	protected, active, err := w.cleanupState(ctx)
	if err != nil {
		w.logger.Warn("docker cleanup: could not read deployment state, skipping orphan images", "error", err)
		return nil, true, 0
	}
	if active > 0 {
		return nil, true, len(protected)
	}

	psOut, err := w.ext.docker(ctx, dockerCall{Args: []string{"ps", "-a", "--no-trunc", "--format", "{{.Image}}"}})
	if err != nil {
		w.logger.Warn("docker cleanup: docker ps failed, skipping orphan images", "error", strings.TrimSpace(string(psOut)))
		return nil, true, len(protected)
	}
	inUse := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(string(psOut)), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			inUse[l] = true
		}
	}

	imgOut, err := w.ext.docker(ctx, dockerCall{Args: []string{"images", "--no-trunc", "--format", "{{.Repository}}|{{.Tag}}|{{.ID}}"}})
	if err != nil {
		return nil, true, len(protected)
	}
	seenECR := map[string]bool{}
	for _, im := range parseImages(string(imgOut)) {
		ref := im.Repo + ":" + im.Tag
		if inUse[ref] || inUse[im.Repo] || inUse[im.ID] || inUse[strings.TrimPrefix(im.ID, "sha256:")] {
			continue
		}
		remove := false
		if m := appImageRe.FindStringSubmatch(im.Repo); m != nil {
			remove = !protected[m[1]]
		} else if strings.Contains(im.Repo, "/capsule-apps/") {
			// Local copy of an image pushed to ECR: keep the newest tag per repo
			// (`docker images` lists newest first), drop older ones.
			if !seenECR[im.Repo] {
				seenECR[im.Repo] = true
			} else {
				remove = true
			}
		}
		if !remove {
			continue
		}
		if out, err := w.ext.docker(ctx, dockerCall{Args: []string{"rmi", ref}}); err != nil {
			w.logger.Warn("docker cleanup: could not remove image", "image", ref, "error", strings.TrimSpace(string(out)))
			continue
		}
		removed = append(removed, ref)
	}
	return removed, false, len(protected)
}

// cleanupState returns the 12-char project short ids that have a successful
// deployment (protected) and the number of in-flight deployments.
func (w *DeployWorker) cleanupState(ctx context.Context) (map[string]bool, int, error) {
	if w.ext.protected != nil {
		return w.ext.protected(ctx)
	}
	rows, err := w.pool.Query(ctx, protectedProjectsSQL)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	prot := map[string]bool{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, 0, err
		}
		prot[s] = true
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	var active int
	if err := w.pool.QueryRow(ctx, activeDeploymentsSQL).Scan(&active); err != nil {
		return nil, 0, err
	}
	return prot, active, nil
}
