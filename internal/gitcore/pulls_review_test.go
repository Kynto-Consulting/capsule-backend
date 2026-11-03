package gitcore_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitcore/fake"
)

// reviewRig is a minimal Forgejo double for the two B8 calls (the shared fake of A1 does not
// route them and is not edited from B8).
type reviewRig struct {
	mu   sync.Mutex
	reqs []string
	body map[string]any
	code int
}

func (rr *reviewRig) serve(t *testing.T) *gitcore.Service {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rr.mu.Lock()
		rr.reqs = append(rr.reqs, r.Method+" "+r.URL.Path+" sudo="+r.Header.Get("Sudo"))
		rr.body = nil
		_ = json.Unmarshal(b, &rr.body)
		code := rr.code
		rr.mu.Unlock()
		if r.Header.Get("Authorization") != "token "+fake.Token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if code != 0 {
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"message":"nope"}`))
			return
		}
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/dismissals"):
			_, _ = w.Write([]byte(`{"id":9,"state":"APPROVED","dismissed":true,"user":{"login":"bob"},"commit_id":"abc"}`))
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/requested_reviewers"):
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return gitcore.New(cfgFor(srv.URL), nil, nil)
}

func TestDismissReview(t *testing.T) {
	rr := &reviewRig{}
	s := rr.serve(t)
	ctx := gitcore.WithActor(context.Background(), "alice")
	rv, err := s.DismissReview(ctx, R, 3, 9, "  stale after force push ")
	if err != nil {
		t.Fatal(err)
	}
	if rv.ID != 9 || rv.State != "dismissed" || rv.Author.Login != "bob" {
		t.Fatalf("review: %+v", rv)
	}
	if got := rr.reqs[0]; got != "POST /api/v1/repos/acme/web/pulls/3/reviews/9/dismissals sudo=alice" {
		t.Fatalf("request: %s", got)
	}
	if rr.body["message"] != "stale after force push" {
		t.Fatalf("body: %v", rr.body)
	}
	for _, bad := range []struct {
		n  int
		id int64
		m  string
	}{{0, 1, "x"}, {1, 0, "x"}, {1, 1, "   "}} {
		_, err := s.DismissReview(context.Background(), R, bad.n, bad.id, bad.m)
		wantCode(t, err, gitcore.CodeInvalid)
	}
}

func TestDismissReviewErrorsMapAndDoNotLeakToken(t *testing.T) {
	for code, want := range map[int]gitcore.Code{404: gitcore.CodeNotFound, 403: gitcore.CodeForbidden, 422: gitcore.CodeUnprocessed} {
		rr := &reviewRig{code: code}
		s := rr.serve(t)
		_, err := s.DismissReview(context.Background(), R, 1, 1, "motivo")
		wantCode(t, err, want)
		if strings.Contains(err.Error(), fake.Token) {
			t.Fatal("token leaked in error")
		}
	}
}

func TestRemoveReviewRequest(t *testing.T) {
	rr := &reviewRig{}
	s := rr.serve(t)
	if err := s.RemoveReviewRequest(context.Background(), R, 4, []string{"bob"}, nil); err != nil {
		t.Fatal(err)
	}
	if rr.reqs[0] != "DELETE /api/v1/repos/acme/web/pulls/4/requested_reviewers sudo=" {
		t.Fatalf("request: %s", rr.reqs[0])
	}
	users, _ := rr.body["reviewers"].([]any)
	teams, ok := rr.body["team_reviewers"].([]any)
	if len(users) != 1 || users[0] != "bob" || !ok || len(teams) != 0 {
		t.Fatalf("body must carry [] not null for teams: %v", rr.body)
	}
	n := len(rr.reqs)
	if err := s.RemoveReviewRequest(context.Background(), R, 4, nil, nil); err != nil || len(rr.reqs) != n {
		t.Fatalf("empty call must be a no-op: %v", err)
	}
	// unknown login upstream: nothing to withdraw, not an error
	rr2 := &reviewRig{code: 404}
	if err := rr2.serve(t).RemoveReviewRequest(context.Background(), R, 4, []string{"ghost"}, nil); err != nil {
		t.Fatalf("404 must be ignored: %v", err)
	}
	// forbidden is reported
	rr3 := &reviewRig{code: 403}
	wantCode(t, rr3.serve(t).RemoveReviewRequest(context.Background(), R, 4, []string{"bob"}, nil), gitcore.CodeForbidden)
}
