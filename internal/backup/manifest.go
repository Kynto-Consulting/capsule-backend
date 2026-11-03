package backup

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ManifestSchema is bumped on any incompatible change to the manifest/inventory format.
// See docs/BACKUPS_MANIFEST.md.
const ManifestSchema = 1

// Manifest records what is needed to re-create a project's containers after a total loss:
// references only, never secret values (env var values live encrypted in Capsule's database,
// database credentials too).
type Manifest struct {
	Schema      int                `json:"schema"`
	GeneratedAt time.Time          `json:"generated_at"`
	RunID       uuid.UUID          `json:"run_id"`
	Project     ManifestProject    `json:"project"`
	Deployment  *ManifestDeploy    `json:"deployment,omitempty"`
	Container   *ManifestContainer `json:"container,omitempty"`
	Volumes     []ManifestVolume   `json:"volumes"`
	EnvVarNames []string           `json:"env_var_names"`
	Databases   []ManifestDatabase `json:"databases"`
}

type ManifestProject struct {
	ID         uuid.UUID `json:"id"`
	OrgID      uuid.UUID `json:"org_id"`
	Slug       string    `json:"slug"`
	Runtime    string    `json:"runtime"`
	DeployType string    `json:"deploy_type"`
	HealthPath string    `json:"health_path,omitempty"`
}

type ManifestDeploy struct {
	ID            uuid.UUID `json:"id"`
	Version       string    `json:"version"`
	GitSHA        string    `json:"git_sha,omitempty"`
	ImageTag      string    `json:"image_tag"`
	ImageID       string    `json:"image_id,omitempty"`
	ImageDigests  []string  `json:"image_digests,omitempty"`
	SourceKey     string    `json:"source_key,omitempty"` // deployments/<projectID>/<uuid>.tar.gz in the artifacts bucket
	ContainerPort int       `json:"container_port,omitempty"`
	HostPort      int       `json:"host_port,omitempty"`
}

type ManifestPort struct {
	ContainerPort string `json:"container_port"` // e.g. "3000/tcp"
	HostPort      string `json:"host_port"`
}

type ManifestContainer struct {
	Name          string         `json:"name"`
	Image         string         `json:"image"`
	RestartPolicy string         `json:"restart_policy"`
	Networks      []string       `json:"networks"`
	MemoryBytes   int64          `json:"memory_limit_bytes"`
	NanoCPUs      int64          `json:"cpu_limit_nanos"`
	Ports         []ManifestPort `json:"published_ports"`
	HealthTest    []string       `json:"health_test,omitempty"`
}

type ManifestVolume struct {
	Name       string `json:"name"`
	MountPoint string `json:"mount_point"`
}

type ManifestDatabase struct {
	ID            uuid.UUID        `json:"id"`
	Name          string           `json:"name"`
	Engine        string           `json:"engine"`
	Version       string           `json:"version"`
	Image         string           `json:"image,omitempty"`
	DBName        string           `json:"db_name"`
	HostPort      int              `json:"host_port"`
	Container     string           `json:"container"`
	Volumes       []ManifestVolume `json:"volumes"`
	RestartPolicy string           `json:"restart_policy,omitempty"`
	Present       bool             `json:"container_present"`
}

// inspectDoc is the subset of `docker inspect` we read. Env is parsed for names only.
type inspectDoc struct {
	Name   string                  `json:"Name"`
	Image  string                  `json:"Image"`
	State  struct{ Status string } `json:"State"`
	Config struct {
		Image       string   `json:"Image"`
		Env         []string `json:"Env"`
		Healthcheck *struct {
			Test []string `json:"Test"`
		} `json:"Healthcheck"`
	} `json:"Config"`
	HostConfig struct {
		RestartPolicy struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
		Memory   int64 `json:"Memory"`
		NanoCpus int64 `json:"NanoCpus"`
	} `json:"HostConfig"`
	Mounts []struct {
		Type        string `json:"Type"`
		Name        string `json:"Name"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
	} `json:"Mounts"`
	NetworkSettings struct {
		Networks map[string]json.RawMessage                     `json:"Networks"`
		Ports    map[string][]struct{ HostIp, HostPort string } `json:"Ports"`
	} `json:"NetworkSettings"`
}

func inspectContainer(ctx context.Context, d Docker, name string) (*inspectDoc, error) {
	out, err := d.Run(ctx, Cmd{Args: []string{"inspect", name}})
	if err != nil {
		return nil, err
	}
	var docs []inspectDoc
	if err := json.Unmarshal(out, &docs); err != nil || len(docs) == 0 {
		return nil, ErrNotFound
	}
	return &docs[0], nil
}

func (i *inspectDoc) volumes() []ManifestVolume {
	vols := []ManifestVolume{}
	for _, m := range i.Mounts {
		if m.Type == "volume" {
			vols = append(vols, ManifestVolume{Name: m.Name, MountPoint: m.Destination})
		}
	}
	return vols
}

func (i *inspectDoc) networks() []string {
	n := []string{}
	for k := range i.NetworkSettings.Networks {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

func (i *inspectDoc) ports() []ManifestPort {
	p := []ManifestPort{}
	for cp, binds := range i.NetworkSettings.Ports {
		for _, b := range binds {
			p = append(p, ManifestPort{ContainerPort: cp, HostPort: b.HostPort})
		}
	}
	sort.Slice(p, func(a, b int) bool { return p[a].ContainerPort < p[b].ContainerPort })
	return p
}

func envNames(env []string) []string {
	out := []string{}
	for _, e := range env {
		if k, _, ok := strings.Cut(e, "="); ok && k != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// appContainerName mirrors the deploy worker: capsule-app-<first 12 hex chars of the project id>.
func appContainerName(projectID uuid.UUID) string {
	return "capsule-app-" + strings.ReplaceAll(projectID.String(), "-", "")[:12]
}

func dataVolumeName(projectID uuid.UUID) string { return "capsule-data-" + projectID.String() }

func dbContainerName(id uuid.UUID) string { return "capsule-db-" + id.String() }

func itoa(i int) string { return strconv.Itoa(i) }
