package fn

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Builds: `capsule fn deploy --source <dir>` (and `capsule fn build`) upload a directory with a Dockerfile; the deploy worker of
// the backend builds it with the same builder it uses for projects (one build at a time on the host, the same queue loop), pushes
// it to the ECR repository Capsule manages for the function (capsule/fn-<12 hex of the function id>) and pins the function to
// the pushed digest. The function cannot run until its first build succeeds.

// Build states.
const (
	BuildQueued    = "queued"
	BuildBuilding  = "building"
	BuildSucceeded = "succeeded"
	BuildFailed    = "failed"
)

// MaxBuildAttempts is how many times a build interrupted by a backend restart is picked up again before it fails.
const MaxBuildAttempts = 3

// ErrNoImage: the function was deployed from source and its image is not built yet (or its build failed).
var ErrNoImage = errors.New("fn: the function has no image yet: its build is queued, running or failed (capsule fn builds <name>)")

// sourceKeyRe is the only shape of upload the backend builds: fn-builds/<project id>/<random id>.tar.gz in the artifacts bucket.
var sourceKeyRe = regexp.MustCompile(`^fn-builds/[0-9a-f-]{36}/[0-9a-f-]{36}\.tar\.gz$`)

// SourceKey is where the CLI uploads the packed directory of a build of the project.
func SourceKey(projectID uuid.UUID) string {
	return "fn-builds/" + projectID.String() + "/" + uuid.New().String() + ".tar.gz"
}

// Build is one image build of a function.
type Build struct {
	ID         uuid.UUID  `json:"id"`
	FunctionID uuid.UUID  `json:"function_id"`
	ProjectID  uuid.UUID  `json:"project_id"`
	OrgID      uuid.UUID  `json:"org_id"`
	Function   string     `json:"function"`
	Runtime    string     `json:"runtime"`
	Status     string     `json:"status"`
	SourceKey  string     `json:"-"`
	Image      string     `json:"image,omitempty"`
	Error      string     `json:"error,omitempty"`
	Log        string     `json:"log,omitempty"`
	Attempts   int        `json:"attempts"`
	CreatedBy  *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// BuildStore persists builds. ClaimBuild moves the oldest queued build to building (ErrNotFound when there is none);
// CreateBuild returns ErrConflict when the function already has a build queued or building.
type BuildStore interface {
	CreateBuild(ctx context.Context, b *Build) error
	GetBuild(ctx context.Context, id uuid.UUID) (*Build, error)
	ListBuilds(ctx context.Context, functionID uuid.UUID, limit int) ([]*Build, error)
	ClaimBuild(ctx context.Context, now time.Time) (*Build, error)
	AppendBuildLog(ctx context.Context, id uuid.UUID, text string) error
	FinishBuild(ctx context.Context, id uuid.UUID, status, image, msg string, now time.Time) error
	// ReapBuilds puts back in the queue builds left in building since before `before` (a restart killed them), or fails them
	// after MaxBuildAttempts. It returns how many it touched.
	ReapBuilds(ctx context.Context, before, now time.Time) (int, error)
	SetFunctionImage(ctx context.Context, functionID uuid.UUID, image string) error
}

// ImageRegistry removes the repository Capsule created for a function's images (nil: nothing to remove).
type ImageRegistry interface {
	RemoveFunctionImages(ctx context.Context, f *Function) error
}

// AuditEntry is one row of the audit log written for a function change.
type AuditEntry struct {
	OrgID      uuid.UUID
	ProjectID  uuid.UUID
	UserID     *uuid.UUID
	Action     string // fn.deploy, fn.build.queued, fn.build.succeeded, fn.build.failed, fn.delete
	ResourceID uuid.UUID
	IP         string
	Values     map[string]any
}

// Auditor writes audit rows; failures never fail the operation.
type Auditor func(ctx context.Context, e AuditEntry)

func (s *Service) audit(ctx context.Context, e AuditEntry) {
	if s.Audit != nil {
		s.Audit(context.WithoutCancel(ctx), e)
	}
}

// FnRepository is the ECR repository of the images Capsule builds for f.
func FnRepository(f *Function) string {
	return "capsule/fn-" + strings.ReplaceAll(f.ID.String(), "-", "")[:12]
}

// DeployFromSource creates the function without an image and queues its first build.
func (s *Service) DeployFromSource(ctx context.Context, orgID, projectID uuid.UUID, by *uuid.UUID, spec Spec) (*Function, *Build, error) {
	if s.Builds == nil {
		return nil, nil, invalid("building functions from source is not enabled on this Capsule; publish an image and use --image")
	}
	if spec.SourceKey == "" {
		return nil, nil, invalid("source_key is required")
	}
	f, err := s.Deploy(ctx, orgID, projectID, by, spec)
	if err != nil {
		return nil, nil, err
	}
	b, err := s.QueueBuild(ctx, f, spec.SourceKey, by)
	if err != nil {
		_ = s.Store.DeleteFunction(ctx, f.ID) // a function that can never get an image is not left behind
		return nil, nil, err
	}
	return f, b, nil
}

// QueueBuild queues a build of f from an uploaded source. The worker picks it in the same loop as project deployments.
func (s *Service) QueueBuild(ctx context.Context, f *Function, sourceKey string, by *uuid.UUID) (*Build, error) {
	if s.Builds == nil {
		return nil, invalid("building functions from source is not enabled on this Capsule")
	}
	if !sourceKeyRe.MatchString(sourceKey) || !strings.HasPrefix(sourceKey, "fn-builds/"+f.ProjectID.String()+"/") {
		return nil, invalid("source_key must be an upload of this project (POST .../fn/uploads)")
	}
	b := &Build{ID: uuid.New(), FunctionID: f.ID, ProjectID: f.ProjectID, OrgID: f.OrgID, Function: f.Name, Runtime: f.Runtime,
		Status: BuildQueued, SourceKey: sourceKey, CreatedBy: by, CreatedAt: s.now()}
	if err := s.Builds.CreateBuild(ctx, b); err != nil {
		if errors.Is(err, ErrConflict) {
			return nil, fmt.Errorf("%w: a build of %s is already queued or running", ErrConflict, f.Name)
		}
		return nil, err
	}
	return b, nil
}

// ClaimBuild hands the oldest queued build (and its function) to the worker; nil when there is none.
func (s *Service) ClaimBuild(ctx context.Context) (*Build, *Function, error) {
	if s.Builds == nil {
		return nil, nil, nil
	}
	b, err := s.Builds.ClaimBuild(ctx, s.now())
	if errors.Is(err, ErrNotFound) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	f, err := s.Store.GetFunctionByID(ctx, b.FunctionID)
	if err != nil {
		s.FailBuild(ctx, b, "the function was deleted before its build started")
		return nil, nil, nil
	}
	return b, f, nil
}

// BuildLog appends text (one or more lines) to the build's log.
func (s *Service) BuildLog(ctx context.Context, id uuid.UUID, text string) {
	if s.Builds != nil && text != "" {
		_ = s.Builds.AppendBuildLog(context.WithoutCancel(ctx), id, strings.TrimRight(text, "\n")+"\n")
	}
}

// CompleteBuild pins the function to the pushed image. For the lambda runtime the Lambda is created or updated now, so an image
// AWS cannot run (wrong manifest, wrong base, missing handler) fails the build instead of the first run.
func (s *Service) CompleteBuild(ctx context.Context, b *Build, image string) error {
	f, err := s.Store.GetFunctionByID(ctx, b.FunctionID)
	if err != nil {
		return errors.New("the function was deleted while it was being built")
	}
	if f.Runtime == RuntimeLambda && s.Lambda != nil {
		s.BuildLog(ctx, b.ID, "Preparing the Lambda "+LambdaName(f)+" with the new image...")
		if err := s.Lambda.Ensure(ctx, f, image); err != nil {
			return fmt.Errorf("AWS Lambda did not accept the image: %w", err)
		}
	}
	if err := s.Builds.SetFunctionImage(ctx, f.ID, image); err != nil {
		return err
	}
	if err := s.Builds.FinishBuild(ctx, b.ID, BuildSucceeded, image, "", s.now()); err != nil {
		return err
	}
	s.audit(ctx, AuditEntry{OrgID: b.OrgID, ProjectID: b.ProjectID, UserID: b.CreatedBy, Action: "fn.build.succeeded", ResourceID: f.ID,
		Values: map[string]any{"function": f.Name, "build_id": b.ID.String(), "image": image, "runtime": f.Runtime}})
	return nil
}

// FailBuild records a failed build; the function keeps its previous image (if any).
func (s *Service) FailBuild(ctx context.Context, b *Build, msg string) {
	if s.Builds == nil {
		return
	}
	ctx = context.WithoutCancel(ctx)
	_ = s.Builds.FinishBuild(ctx, b.ID, BuildFailed, "", msg, s.now())
	s.audit(ctx, AuditEntry{OrgID: b.OrgID, ProjectID: b.ProjectID, UserID: b.CreatedBy, Action: "fn.build.failed", ResourceID: b.FunctionID,
		Values: map[string]any{"function": b.Function, "build_id": b.ID.String(), "error": msg}})
}

// ReapBuilds requeues (or fails, after MaxBuildAttempts) builds that stayed in building longer than stale.
func (s *Service) ReapBuilds(ctx context.Context, stale time.Duration) int {
	if s.Builds == nil {
		return 0
	}
	now := s.now()
	n, _ := s.Builds.ReapBuilds(ctx, now.Add(-stale), now)
	return n
}
