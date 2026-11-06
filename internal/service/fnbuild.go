package service

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/fn"
)

// Function images from source (capsule fn deploy --source, docs/vpn-connector.md 7b). The build runs in the same loop as project
// deployments (Run -> processNext, then processFnBuild), so there is never more than one docker build on the host, and under the
// same limits (runLimitedBuild: timeout, memory, concurrency gate). The image goes to the ECR repository Capsule manages for the
// function, capsule/fn-<12 hex of the function id>, and the function is pinned to the pushed digest.

// FnBuilder is what the worker needs from the functions service (*fn.Service).
type FnBuilder interface {
	ClaimBuild(ctx context.Context) (*fn.Build, *fn.Function, error)
	BuildLog(ctx context.Context, id uuid.UUID, text string)
	CompleteBuild(ctx context.Context, b *fn.Build, image string) error
	FailBuild(ctx context.Context, b *fn.Build, msg string)
	ReapBuilds(ctx context.Context, stale time.Duration) int
}

// ecrAPI is the part of *ecr.Client the function builds use.
type ecrAPI interface {
	DescribeRepositories(ctx context.Context, in *ecr.DescribeRepositoriesInput, opts ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error)
	CreateRepository(ctx context.Context, in *ecr.CreateRepositoryInput, opts ...func(*ecr.Options)) (*ecr.CreateRepositoryOutput, error)
	PutLifecyclePolicy(ctx context.Context, in *ecr.PutLifecyclePolicyInput, opts ...func(*ecr.Options)) (*ecr.PutLifecyclePolicyOutput, error)
	SetRepositoryPolicy(ctx context.Context, in *ecr.SetRepositoryPolicyInput, opts ...func(*ecr.Options)) (*ecr.SetRepositoryPolicyOutput, error)
	GetAuthorizationToken(ctx context.Context, in *ecr.GetAuthorizationTokenInput, opts ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error)
	DeleteRepository(ctx context.Context, in *ecr.DeleteRepositoryInput, opts ...func(*ecr.Options)) (*ecr.DeleteRepositoryOutput, error)
}

// fnBuildState holds the function-build seams of the worker (production defaults when nil).
type fnBuildState struct {
	svc      FnBuilder
	ecr      ecrAPI
	registry string                                           // <account>.dkr.ecr.<region>.amazonaws.com
	region   string                                           // for the repository policy condition
	account  string                                           //
	fetch    func(ctx context.Context, key, dir string) error // downloads and extracts the uploaded source
}

// SetFnBuilder enables builds of function images in this worker. Without AWS (no ECR) builds fail with a clear message.
func (w *DeployWorker) SetFnBuilder(b FnBuilder) {
	st := &fnBuildState{svc: b, fetch: w.downloadAndExtract}
	if w.aws != nil && w.aws.ECR != nil {
		st.ecr, st.account, st.region = w.aws.ECR, w.aws.Account, w.aws.Region
		st.registry = w.aws.Account + ".dkr.ecr." + w.aws.Region + ".amazonaws.com"
	}
	w.fnb.Store(st)
}

// processFnBuild runs the oldest queued function build, synchronously (one build at a time). It returns true when it ran one.
func (w *DeployWorker) processFnBuild(ctx context.Context) bool {
	st := w.fnb.Load()
	if st == nil || st.svc == nil {
		return false
	}
	w.ext.init()
	// a build left in "building" by a restart goes back to the queue once its time limit (plus the push) has clearly passed
	if n := st.svc.ReapBuilds(ctx, w.ext.cfg.BuildTimeout+30*time.Minute); n > 0 {
		w.logger.Info("deploy worker: requeued interrupted function builds", "count", n)
	}
	b, f, err := st.svc.ClaimBuild(ctx)
	if err != nil {
		w.logger.Error("deploy worker: claim function build", "error", err)
		return false
	}
	if b == nil {
		return false
	}
	w.wg.Add(1)
	defer w.wg.Done()
	w.runFnBuild(ctx, st, b, f)
	return true
}

func (w *DeployWorker) runFnBuild(ctx context.Context, st *fnBuildState, b *fn.Build, f *fn.Function) {
	logf := func(m string) { st.svc.BuildLog(ctx, b.ID, m) }
	fail := func(m string) {
		logf("ERROR: " + m)
		st.svc.FailBuild(ctx, b, m)
		w.logger.Warn("deploy worker: function build failed", "build", b.ID, "function", f.Name, "error", m)
	}
	logf(fmt.Sprintf("Building the image of function %s (runtime %s, attempt %d)", f.Name, f.Runtime, b.Attempts))
	if st.ecr == nil || st.registry == "" {
		fail("this Capsule has no container registry (AWS ECR) configured, so it cannot build function images; publish an image and use --image")
		return
	}

	dir, err := os.MkdirTemp("", "capsule-fnbuild-*")
	if err != nil {
		fail("cannot create the build directory: " + err.Error())
		return
	}
	defer os.RemoveAll(dir)
	if err := st.fetch(ctx, b.SourceKey, dir); err != nil {
		fail("cannot download the uploaded source: " + err.Error())
		return
	}
	dockerfile := filepath.Join(dir, "Dockerfile")
	if _, err := os.Stat(dockerfile); err != nil {
		fail("the uploaded directory has no Dockerfile at its root (see docs/vpn-connector.md 7b for one per runtime)")
		return
	}
	if f.Runtime == fn.RuntimeLambda {
		warn, err := checkLambdaBase(dockerfile)
		if err != nil {
			fail(err.Error())
			return
		}
		if warn != "" {
			logf("WARNING: " + warn)
		}
	}

	repo := fn.FnRepository(f)
	logf("Ensuring ECR repository " + repo)
	if err := ensureFnRepo(ctx, st, repo, logf); err != nil {
		fail("cannot prepare the ECR repository " + repo + ": " + err.Error())
		return
	}
	if err := w.ecrLogin(ctx, st); err != nil {
		fail("cannot log in to ECR: " + err.Error())
		return
	}
	tag := st.registry + "/" + repo + ":b-" + strings.ReplaceAll(b.ID.String(), "-", "")[:12]
	logf("Building " + tag + " (linux/amd64)")
	res := w.runLimitedBuild(ctx, buildSpec{Dir: dir, Tag: tag, Platform: "linux/amd64", DockerfilePath: dockerfile, Log: logf})
	logf(tailLines(string(res.Output), 400))
	if res.Err != nil {
		fail(res.Err.Error())
		return
	}
	logf("Pushing " + tag)
	out, err := w.dock(ctx, "push", tag)
	logf(tailLines(string(out), 60))
	if err != nil {
		fail("docker push failed: " + err.Error())
		return
	}
	image := tag
	if d := repoDigest(w.dockInspectDigests(ctx, tag), st.registry+"/"+repo); d != "" {
		image = d // pinned: a later push of the same tag never changes what the function runs
	}
	_, _ = w.dock(ctx, "rmi", tag) // the host keeps no copy of function images; BuildKit's cache stays for the next build

	if err := st.svc.CompleteBuild(ctx, b, image); err != nil {
		fail(err.Error())
		return
	}
	logf("Image ready: " + image)
	w.logger.Info("deploy worker: function build succeeded", "build", b.ID, "function", f.Name, "image", image)
}

// ensureFnRepo creates the function's repository (immutable tags, scan on push) with a lifecycle policy that keeps the last
// 10 images and a policy that lets Lambda pull from it. An existing repository is reused as is.
func ensureFnRepo(ctx context.Context, st *fnBuildState, repo string, logf func(string)) error {
	if _, err := st.ecr.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{RepositoryNames: []string{repo}}); err == nil {
		return nil
	}
	_, err := st.ecr.CreateRepository(ctx, &ecr.CreateRepositoryInput{
		RepositoryName:             aws.String(repo),
		ImageTagMutability:         ecrtypes.ImageTagMutabilityImmutable,
		ImageScanningConfiguration: &ecrtypes.ImageScanningConfiguration{ScanOnPush: true},
		Tags:                       []ecrtypes.Tag{{Key: aws.String("capsule"), Value: aws.String("fn")}},
	})
	var exists *ecrtypes.RepositoryAlreadyExistsException
	if err != nil && !errors.As(err, &exists) {
		return err
	}
	lifecycle := `{"rules":[{"rulePriority":1,"description":"keep the last 10 images","selection":{"tagStatus":"any","countType":"imageCountMoreThan","countNumber":10},"action":{"type":"expire"}}]}`
	if _, err := st.ecr.PutLifecyclePolicy(ctx, &ecr.PutLifecyclePolicyInput{RepositoryName: aws.String(repo), LifecyclePolicyText: aws.String(lifecycle)}); err != nil {
		logf("WARNING: lifecycle policy not set: " + err.Error())
	}
	pol, _ := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []map[string]any{{
		"Sid": "LambdaPull", "Effect": "Allow", "Principal": map[string]any{"Service": "lambda.amazonaws.com"},
		"Action":    []string{"ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"},
		"Condition": map[string]any{"StringLike": map[string]string{"aws:sourceArn": "arn:aws:lambda:" + st.region + ":" + st.account + ":function:capsule-fn-*"}},
	}}})
	if _, err := st.ecr.SetRepositoryPolicy(ctx, &ecr.SetRepositoryPolicyInput{RepositoryName: aws.String(repo), PolicyText: aws.String(string(pol))}); err != nil {
		logf("WARNING: repository policy for Lambda not set (Lambda adds it itself when the backend may): " + err.Error())
	}
	return nil
}

// ecrLogin logs docker in to the account's registry with a token from the SDK (no aws CLI on the host). The password goes by stdin.
func (w *DeployWorker) ecrLogin(ctx context.Context, st *fnBuildState) error {
	out, err := st.ecr.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return err
	}
	if len(out.AuthorizationData) == 0 {
		return errors.New("ECR returned no authorization data")
	}
	raw, err := base64.StdEncoding.DecodeString(aws.ToString(out.AuthorizationData[0].AuthorizationToken))
	if err != nil {
		return err
	}
	user, pass, ok := strings.Cut(string(raw), ":")
	if !ok {
		return errors.New("malformed ECR token")
	}
	w.ext.init()
	res, err := w.ext.docker(ctx, dockerCall{Args: []string{"login", "--username", user, "--password-stdin", st.registry}, Stdin: strings.NewReader(pass)})
	if err != nil {
		return fmt.Errorf("docker login: %v: %s", err, strings.TrimSpace(string(res)))
	}
	return nil
}

func (w *DeployWorker) dockInspectDigests(ctx context.Context, tag string) []string {
	out, err := w.dock(ctx, "image", "inspect", "--format", "{{json .RepoDigests}}", tag)
	if err != nil {
		return nil
	}
	var ds []string
	_ = json.Unmarshal([]byte(strings.TrimSpace(string(out))), &ds)
	return ds
}

// repoDigest picks the digest reference of repo (registry/repo@sha256:...) among an image's RepoDigests.
func repoDigest(digests []string, repo string) string {
	for _, d := range digests {
		if strings.HasPrefix(d, repo+"@sha256:") {
			return d
		}
	}
	return ""
}

func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = append([]string{fmt.Sprintf("... (%d earlier lines omitted)", len(lines)-n)}, lines[len(lines)-n:]...)
	}
	return strings.Join(lines, "\n")
}

var (
	fromRe       = regexp.MustCompile(`(?i)^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?\s*$`)
	lambdaNodeRe = regexp.MustCompile(`^(public\.ecr\.aws/lambda/nodejs|amazon/aws-lambda-nodejs)([:@].*)?$`)
)

// checkLambdaBase verifies that the final stage of the Dockerfile is an AWS Lambda base image for Node.js
// (public.ecr.aws/lambda/nodejs or amazon/aws-lambda-nodejs), following stage aliases. A base given by a build argument
// cannot be checked here: that is only a warning (Lambda will refuse a wrong image when the build pins it).
func checkLambdaBase(path string) (warning string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	alias := map[string]string{}
	last := ""
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		m := fromRe.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		img := m[1]
		if a, ok := alias[strings.ToLower(img)]; ok {
			img = a
		}
		if m[2] != "" {
			alias[strings.ToLower(m[2])] = img
		}
		last = img
	}
	switch {
	case last == "":
		return "", errors.New("the Dockerfile has no FROM line")
	case strings.Contains(last, "$"):
		return fmt.Sprintf("the final base image %q comes from a build argument and was not checked; for --runtime lambda it must be public.ecr.aws/lambda/nodejs", last), nil
	case !lambdaNodeRe.MatchString(strings.ToLower(last)):
		return "", fmt.Errorf("for --runtime lambda the final stage of the Dockerfile must be an AWS Lambda base image for Node.js (FROM public.ecr.aws/lambda/nodejs:22), not %q", last)
	}
	return "", nil
}

// FnImageRegistry deletes the ECR repository of a function's built images (fn.ImageRegistry).
type FnImageRegistry struct{ ECR ecrAPI }

// NewFnImageRegistry is the registry of the account's ECR (nil client: nothing is removed).
func NewFnImageRegistry(c *ecr.Client) *FnImageRegistry {
	if c == nil {
		return nil
	}
	return &FnImageRegistry{ECR: c}
}

// RemoveFunctionImages deletes capsule/fn-<id> with its images; a repository that does not exist is not an error.
func (r *FnImageRegistry) RemoveFunctionImages(ctx context.Context, f *fn.Function) error {
	if r == nil || r.ECR == nil {
		return nil
	}
	_, err := r.ECR.DeleteRepository(ctx, &ecr.DeleteRepositoryInput{RepositoryName: aws.String(fn.FnRepository(f)), Force: true})
	var nf *ecrtypes.RepositoryNotFoundException
	if err != nil && !errors.As(err, &nf) {
		return err
	}
	return nil
}
