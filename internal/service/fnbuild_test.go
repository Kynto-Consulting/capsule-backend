package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/fn"
	"github.com/kynto/capsule/backend/internal/vpn"
)

type fakeECR struct {
	mu       sync.Mutex
	repos    map[string]bool
	policies []string
	deleted  []string
}

func (f *fakeECR) DescribeRepositories(_ context.Context, in *ecr.DescribeRepositoriesInput, _ ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
	if f.repos[in.RepositoryNames[0]] {
		return &ecr.DescribeRepositoriesOutput{}, nil
	}
	return nil, &ecrtypes.RepositoryNotFoundException{}
}
func (f *fakeECR) CreateRepository(_ context.Context, in *ecr.CreateRepositoryInput, _ ...func(*ecr.Options)) (*ecr.CreateRepositoryOutput, error) {
	f.repos[*in.RepositoryName] = true
	return &ecr.CreateRepositoryOutput{}, nil
}
func (f *fakeECR) PutLifecyclePolicy(_ context.Context, _ *ecr.PutLifecyclePolicyInput, _ ...func(*ecr.Options)) (*ecr.PutLifecyclePolicyOutput, error) {
	return &ecr.PutLifecyclePolicyOutput{}, nil
}
func (f *fakeECR) SetRepositoryPolicy(_ context.Context, in *ecr.SetRepositoryPolicyInput, _ ...func(*ecr.Options)) (*ecr.SetRepositoryPolicyOutput, error) {
	f.policies = append(f.policies, *in.PolicyText)
	return &ecr.SetRepositoryPolicyOutput{}, nil
}
func (f *fakeECR) GetAuthorizationToken(_ context.Context, _ *ecr.GetAuthorizationTokenInput, _ ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error) {
	tok := base64.StdEncoding.EncodeToString([]byte("AWS:ecr-password"))
	return &ecr.GetAuthorizationTokenOutput{AuthorizationData: []ecrtypes.AuthorizationData{{AuthorizationToken: aws.String(tok)}}}, nil
}
func (f *fakeECR) DeleteRepository(_ context.Context, in *ecr.DeleteRepositoryInput, _ ...func(*ecr.Options)) (*ecr.DeleteRepositoryOutput, error) {
	if !f.repos[*in.RepositoryName] {
		return nil, &ecrtypes.RepositoryNotFoundException{}
	}
	f.deleted = append(f.deleted, *in.RepositoryName)
	delete(f.repos, *in.RepositoryName)
	return &ecr.DeleteRepositoryOutput{}, nil
}

type fnRig struct {
	w      *DeployWorker
	svc    *fn.Service
	ecr    *fakeECR
	calls  []string
	stdin  string
	org    uuid.UUID
	proj   uuid.UUID
	files  map[string]string // the uploaded directory
	failOn string
}

func newFnRig(t *testing.T) *fnRig {
	t.Helper()
	r := &fnRig{ecr: &fakeECR{repos: map[string]bool{}}, org: uuid.New(), proj: uuid.New()}
	store := fn.NewMemStore()
	r.svc = &fn.Service{Store: store, Builds: store, VPN: &vpn.Service{Store: vpn.NewMemStore(), SecretKey: "unit-test-key-0123456789abcdef"}}
	r.w = buildWorker(DefaultDeployConfig(), func(_ context.Context, c dockerCall) ([]byte, error) {
		cmd := strings.Join(c.Args, " ")
		r.calls = append(r.calls, cmd)
		if c.Stdin != nil {
			b, _ := io.ReadAll(c.Stdin)
			r.stdin = string(b)
		}
		if r.failOn != "" && strings.HasPrefix(cmd, r.failOn) {
			return []byte("boom"), errors.New("exit status 1")
		}
		if strings.HasPrefix(cmd, "image inspect") {
			repo := strings.Split(c.Args[len(c.Args)-1], ":b-")[0]
			ds, _ := json.Marshal([]string{"other/repo@sha256:00", repo + "@sha256:abc123"})
			return ds, nil
		}
		return []byte("ok"), nil
	})
	r.w.fnb.Store(&fnBuildState{svc: r.svc, ecr: r.ecr, registry: "123.dkr.ecr.us-east-1.amazonaws.com", region: "us-east-1", account: "123",
		fetch: func(_ context.Context, key, dir string) error {
			if !strings.HasPrefix(key, "fn-builds/"+r.proj.String()+"/") {
				return errors.New("wrong key")
			}
			for n, c := range r.files {
				if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644); err != nil {
					return err
				}
			}
			return nil
		}})
	return r
}

func (r *fnRig) deploy(t *testing.T, runtime string) (*fn.Function, *fn.Build) {
	t.Helper()
	f, b, err := r.svc.DeployFromSource(context.Background(), r.org, r.proj, nil, fn.Spec{Name: "copiar", Runtime: runtime, SourceKey: fn.SourceKey(r.proj)})
	if err != nil {
		t.Fatal(err)
	}
	return f, b
}

func TestFnBuildFromSourcePushesToTheManagedRepoAndPinsTheDigest(t *testing.T) {
	r := newFnRig(t)
	r.files = map[string]string{"Dockerfile": "FROM node:22 AS deps\nRUN npm ci\nFROM public.ecr.aws/lambda/nodejs:22\nCOPY . .\nCMD [\"index.handler\"]\n"}
	r.svc.Lambda = nil // container runtime here; the lambda path is covered below
	f, b := r.deploy(t, "container")
	if _, err := r.svc.Enqueue(context.Background(), f, fn.TriggerAPI, "user:ana", nil); !errors.Is(err, fn.ErrNoImage) {
		t.Fatalf("a function without its image cannot run: %v", err)
	}
	if !r.w.processFnBuild(context.Background()) {
		t.Fatal("the queued build was not processed")
	}
	got, _ := r.svc.Builds.GetBuild(context.Background(), b.ID)
	repo := "capsule/fn-" + strings.ReplaceAll(f.ID.String(), "-", "")[:12]
	want := "123.dkr.ecr.us-east-1.amazonaws.com/" + repo + "@sha256:abc123"
	if got.Status != fn.BuildSucceeded || got.Image != want {
		t.Fatalf("build: %s %q\n%s", got.Status, got.Image, got.Log)
	}
	f2, _ := r.svc.Store.GetFunctionByID(context.Background(), f.ID)
	if f2.Image != want {
		t.Fatalf("function pinned to %q", f2.Image)
	}
	if !r.ecr.repos[repo] || len(r.ecr.policies) != 1 || !strings.Contains(r.ecr.policies[0], "capsule-fn-*") {
		t.Fatalf("repo %v policies %v", r.ecr.repos, r.ecr.policies)
	}
	if r.stdin != "ecr-password" || strings.Contains(strings.Join(r.calls, "\n"), "ecr-password") {
		t.Fatal("the registry password goes by stdin, never in argv")
	}
	joined := strings.Join(r.calls, "\n")
	for _, w := range []string{"login --username AWS --password-stdin 123.dkr.ecr.us-east-1.amazonaws.com", "--platform linux/amd64", "push 123.dkr.ecr.us-east-1.amazonaws.com/" + repo + ":b-", "rmi "} {
		if !strings.Contains(joined, w) {
			t.Fatalf("missing docker call %q in\n%s", w, joined)
		}
	}
	if _, err := r.svc.Enqueue(context.Background(), f2, fn.TriggerAPI, "user:ana", nil); err != nil {
		t.Fatalf("after the build the function runs: %v", err)
	}
	if r.w.processFnBuild(context.Background()) {
		t.Fatal("nothing left to build")
	}
	// deleting the function deletes its image repository
	r.svc.Registry = &FnImageRegistry{ECR: r.ecr}
	if err := r.svc.Delete(context.Background(), f2); err != nil || len(r.ecr.deleted) != 1 {
		t.Fatalf("delete: %v %v", err, r.ecr.deleted)
	}
}

func TestFnBuildLambdaChecksTheBaseImageAndOneBuildAtATime(t *testing.T) {
	r := newFnRig(t)
	r.svc.Lambda = &fn.LambdaExecutor{} // enabled (not invoked: the build fails before)
	r.files = map[string]string{"Dockerfile": "FROM node:22-slim\nCMD [\"node\",\"index.js\"]\n"}
	f, b := r.deploy(t, "lambda")
	if _, err := r.svc.QueueBuild(context.Background(), f, fn.SourceKey(r.proj), nil); !errors.Is(err, fn.ErrConflict) {
		t.Fatalf("a second build while one is queued must be refused: %v", err)
	}
	r.w.processFnBuild(context.Background())
	got, _ := r.svc.Builds.GetBuild(context.Background(), b.ID)
	if got.Status != fn.BuildFailed || !strings.Contains(got.Error, "public.ecr.aws/lambda/nodejs") {
		t.Fatalf("%s %q", got.Status, got.Error)
	}
	for _, c := range r.calls {
		if strings.HasPrefix(c, "build") || strings.HasPrefix(c, "push") {
			t.Fatal("nothing is built with a wrong base")
		}
	}
	// no Dockerfile at all
	r.files = map[string]string{"index.js": "x"}
	b2, err := r.svc.QueueBuild(context.Background(), f, fn.SourceKey(r.proj), nil)
	if err != nil {
		t.Fatal(err)
	}
	r.w.processFnBuild(context.Background())
	got, _ = r.svc.Builds.GetBuild(context.Background(), b2.ID)
	if got.Status != fn.BuildFailed || !strings.Contains(got.Error, "no Dockerfile") {
		t.Fatalf("%s %q", got.Status, got.Error)
	}
	// a source of another project is refused
	if _, err := r.svc.QueueBuild(context.Background(), f, fn.SourceKey(uuid.New()), nil); !errors.Is(err, fn.ErrInvalid) {
		t.Fatalf("foreign source: %v", err)
	}
}

func TestFnBuildFailureKeepsThePreviousImageAndRestartsAreReaped(t *testing.T) {
	r := newFnRig(t)
	r.files = map[string]string{"Dockerfile": "FROM node:22\n"}
	f, _ := r.deploy(t, "container")
	r.w.processFnBuild(context.Background())
	good, _ := r.svc.Store.GetFunctionByID(context.Background(), f.ID)
	r.failOn = "push"
	b, _ := r.svc.QueueBuild(context.Background(), f, fn.SourceKey(r.proj), nil)
	r.w.processFnBuild(context.Background())
	got, _ := r.svc.Builds.GetBuild(context.Background(), b.ID)
	now, _ := r.svc.Store.GetFunctionByID(context.Background(), f.ID)
	if got.Status != fn.BuildFailed || now.Image != good.Image || good.Image == "" {
		t.Fatalf("failed build must keep the image: %s %q -> %q", got.Status, good.Image, now.Image)
	}
	// a build left "building" by a restart is requeued
	r.failOn = ""
	b3, _ := r.svc.QueueBuild(context.Background(), f, fn.SourceKey(r.proj), nil)
	if _, err := r.svc.Builds.ClaimBuild(context.Background(), time.Now().Add(-3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	r.w.processFnBuild(context.Background())
	got, _ = r.svc.Builds.GetBuild(context.Background(), b3.ID)
	if got.Status != fn.BuildSucceeded || got.Attempts != 2 || !strings.Contains(got.Log, "interrupted") {
		t.Fatalf("reaped build: %s attempts %d\n%s", got.Status, got.Attempts, got.Log)
	}
}

func TestCheckLambdaBase(t *testing.T) {
	dir := t.TempDir()
	for df, ok := range map[string]bool{
		"FROM public.ecr.aws/lambda/nodejs:22\n":                              true,
		"FROM --platform=linux/amd64 amazon/aws-lambda-nodejs:20 AS base\n":   true,
		"FROM public.ecr.aws/lambda/nodejs:22 AS base\nFROM base\nCOPY . .\n": true,
		"FROM public.ecr.aws/lambda/nodejs:22\nFROM node:22\n":                false,
		"FROM public.ecr.aws/lambda/python:3.12\n":                            false,
	} {
		p := filepath.Join(dir, "Dockerfile")
		os.WriteFile(p, []byte(df), 0o644)
		_, err := checkLambdaBase(p)
		if (err == nil) != ok {
			t.Errorf("%q: %v", df, err)
		}
	}
	p := filepath.Join(dir, "Dockerfile")
	os.WriteFile(p, []byte("ARG BASE\nFROM ${BASE}\n"), 0o644)
	if w, err := checkLambdaBase(p); err != nil || w == "" {
		t.Fatalf("build-arg base is a warning: %q %v", w, err)
	}
}
