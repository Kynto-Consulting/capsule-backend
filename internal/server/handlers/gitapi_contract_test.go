package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	yaml "go.yaml.in/yaml/v2"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/gitcore"
)

// The contract test walks docs/git-capsule/API.openapi.yaml and checks, for every operation of
// package B1: the route exists, x-permission is enforced per role (403 for a lower role, 404 for a
// hidden project, 403 for a non-member), the success status is the documented one and the response
// body validates against the documented schema.

const gapiContractFile = "../../../../docs/git-capsule/API.openapi.yaml"

type gapiOp struct {
	ID         string
	Method     string
	Path       string
	Permission string
	Success    int // the documented 2xx status
	SuccessRef string
}

var (
	gapiContractOnce sync.Once
	gapiContractDoc  map[string]any
	gapiContractMap  map[string]*gapiOp
)

func gapiYAML(v any) any {
	switch t := v.(type) {
	case map[any]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[fmt.Sprint(k)] = gapiYAML(x)
		}
		return m
	case []any:
		for i := range t {
			t[i] = gapiYAML(t[i])
		}
		return t
	}
	return v
}

func gapiLoadContract(t *testing.T) {
	t.Helper()
	gapiContractOnce.Do(func() {
		raw, err := os.ReadFile(filepath.FromSlash(gapiContractFile))
		if err != nil {
			return
		}
		var d any
		if err := yaml.Unmarshal(raw, &d); err != nil {
			return
		}
		gapiContractDoc = gapiYAML(d).(map[string]any)
		gapiContractMap = map[string]*gapiOp{}
		for path, pv := range gapiContractDoc["paths"].(map[string]any) {
			for method, ov := range pv.(map[string]any) {
				o, ok := ov.(map[string]any)
				if !ok || o["operationId"] == nil {
					continue
				}
				def := &gapiOp{ID: o["operationId"].(string), Method: strings.ToUpper(method), Path: path}
				def.Permission, _ = o["x-permission"].(string)
				for code, rv := range o["responses"].(map[string]any) {
					if n, _ := strconv.Atoi(code); n >= 200 && n < 300 {
						def.Success = n
						if c, ok := rv.(map[string]any)["content"].(map[string]any); ok {
							if js, ok := c["application/json"].(map[string]any); ok {
								def.SuccessRef, _ = js["schema"].(map[string]any)["$ref"].(string)
							}
						}
					}
				}
				gapiContractMap[def.Method+" "+path] = def
			}
		}
	})
	if gapiContractDoc == nil {
		t.Skipf("%s not found or unreadable", gapiContractFile)
	}
}

func gapiContractOps(t *testing.T) map[string]*gapiOp {
	gapiLoadContract(t)
	return gapiContractMap
}

// ---- a small JSON-schema checker for the subset the contract uses ------------------------------

func gapiResolveRef(t *testing.T, s any) map[string]any {
	m, _ := s.(map[string]any)
	if m == nil {
		return nil
	}
	if ref, ok := m["$ref"].(string); ok {
		name := ref[strings.LastIndex(ref, "/")+1:]
		sch, ok := gapiContractDoc["components"].(map[string]any)["schemas"].(map[string]any)[name]
		if !ok {
			t.Fatalf("schema %s not found", name)
		}
		return gapiResolveRef(t, sch)
	}
	return m
}

func gapiTypeAllows(schema map[string]any, kind string) bool {
	switch tt := schema["type"].(type) {
	case string:
		return tt == kind
	case []any:
		for _, x := range tt {
			if x == kind {
				return true
			}
		}
	}
	return false
}

func gapiCheckSchema(t *testing.T, schema any, v any, path string, errs *[]string) {
	s := gapiResolveRef(t, schema)
	if s == nil {
		return
	}
	if one, ok := s["oneOf"].([]any); ok {
		for _, alt := range one {
			var sub []string
			gapiCheckSchema(t, alt, v, path, &sub)
			if len(sub) == 0 {
				return
			}
		}
		*errs = append(*errs, path+": matches none of oneOf")
		return
	}
	bad := func(f string, a ...any) { *errs = append(*errs, path+": "+fmt.Sprintf(f, a...)) }
	if v == nil {
		if s["type"] != nil && !gapiTypeAllows(s, "null") {
			bad("null where %v is expected", s["type"])
		}
		return
	}
	switch val := v.(type) {
	case map[string]any:
		if s["type"] != nil && !gapiTypeAllows(s, "object") {
			bad("object where %v is expected", s["type"])
			return
		}
		if req, ok := s["required"].([]any); ok {
			for _, k := range req {
				if _, present := val[k.(string)]; !present {
					bad("missing required property %q", k)
				}
			}
		}
		if props, ok := s["properties"].(map[string]any); ok {
			keys := make([]string, 0, len(val))
			for k := range val {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if ps, ok := props[k]; ok {
					gapiCheckSchema(t, ps, val[k], path+"."+k, errs)
				}
			}
		}
	case []any:
		if s["type"] != nil && !gapiTypeAllows(s, "array") {
			bad("array where %v is expected", s["type"])
			return
		}
		for i, it := range val {
			gapiCheckSchema(t, s["items"], it, fmt.Sprintf("%s[%d]", path, i), errs)
		}
	case string:
		if s["type"] != nil && !gapiTypeAllows(s, "string") {
			bad("string where %v is expected", s["type"])
			return
		}
		if en, ok := s["enum"].([]any); ok {
			found := false
			for _, e := range en {
				if e == val {
					found = true
				}
			}
			if !found {
				bad("%q is not one of %v", val, en)
			}
		}
		switch s["format"] {
		case "date-time":
			if _, err := time.Parse(time.RFC3339, val); err != nil {
				bad("%q is not a date-time", val)
			}
		case "uuid":
			if _, err := uuid.Parse(val); err != nil {
				bad("%q is not a uuid", val)
			}
		}
	case bool:
		if s["type"] != nil && !gapiTypeAllows(s, "boolean") {
			bad("boolean where %v is expected", s["type"])
		}
	case float64:
		if s["type"] != nil && !gapiTypeAllows(s, "number") && !gapiTypeAllows(s, "integer") {
			bad("number where %v is expected", s["type"])
			return
		}
		if gapiTypeAllows(s, "integer") && !gapiTypeAllows(s, "number") && val != float64(int64(val)) {
			bad("%v is not an integer", val)
		}
	}
}

func TestSchemaCheckerCatchesDrift(t *testing.T) {
	gapiLoadContract(t)
	var errs []string
	gapiCheckSchema(t, map[string]any{"$ref": "#/components/schemas/Pull"}, map[string]any{
		"number": "one", "state": "weird", "created_at": "yesterday", "head": 3.0,
	}, "$", &errs)
	if len(errs) < 4 {
		t.Fatalf("the checker must flag wrong types, enums and formats, got %v", errs)
	}
	errs = nil
	gapiCheckSchema(t, map[string]any{"$ref": "#/components/schemas/BranchList"}, map[string]any{"next_cursor": nil}, "$", &errs)
	if len(errs) != 1 || !strings.Contains(errs[0], "items") {
		t.Fatalf("required items must be enforced: %v", errs)
	}
}

// ---- the operations of package B1 ---------------------------------------------------------------

type gapiSpec struct {
	vars        map[string]string
	query       string
	body        any
	ext         bool   // needs the optional gitcore capabilities (rerun, secrets list, runners, artifacts)
	skipSuccess string // reason the success path cannot run against the fake
}

var gapiB1Ops = map[string]gapiSpec{
	"repoGet":           {},
	"repoProvision":     {body: map[string]any{}, skipSuccess: "provisioning needs the core Git service configured; the route is checked for permissions only"},
	"repoUpdate":        {body: map[string]any{"delete_branch_on_merge": true}},
	"repoTree":          {},
	"repoBlob":          {query: "path=src/app.go"},
	"repoCompare":       {query: "base=main&head=feature"},
	"branchesList":      {},
	"branchCreate":      {body: map[string]any{"name": "topic", "from": "main"}},
	"branchDelete":      {},
	"tagsList":          {},
	"tagCreate":         {body: map[string]any{"name": "v9", "target": "main"}},
	"tagDelete":         {},
	"commitsList":       {},
	"commitGet":         {},
	"commitChecks":      {},
	"pullsList":         {},
	"pullCreate":        {body: map[string]any{"title": "Add y", "head": "feature2", "base": "main"}},
	"pullGet":           {},
	"pullUpdate":        {body: map[string]any{"title": "Renamed"}},
	"pullFiles":         {},
	"pullCommits":       {},
	"reviewsList":       {},
	"reviewCreate":      {body: map[string]any{"event": "comment", "body": "hi"}},
	"commentsList":      {},
	"commentCreate":     {body: map[string]any{"body": "hi"}},
	"pullMerge":         {body: map[string]any{"style": "squash"}},
	"pullUpdateBranch":  {},
	"pullChecks":        {},
	"workflowsList":     {},
	"workflowDispatch":  {body: map[string]any{"ref": "main"}},
	"runsList":          {},
	"runGet":            {},
	"jobLogs":           {},
	"runRerun":          {},
	"runCancel":         {},
	"artifactsList":     {ext: true}, // real core: needs the web session (200 with it, 501 NOT_SUPPORTED without; see TestDispatchRerunCancelAndGuards)
	"ciSecretsList":     {},
	"ciSecretPut":       {vars: map[string]string{"name": "MY_SECRET"}, body: map[string]any{"value": "v"}},
	"ciSecretDelete":    {vars: map[string]string{"name": "MY_SECRET"}},
	"ciVarsList":        {},
	"ciVarPut":          {vars: map[string]string{"name": "MY_VAR"}, body: map[string]any{"value": "v"}},
	"ciVarDelete":       {vars: map[string]string{"name": "MY_VAR"}},
	"orgCiSecretsList":  {},
	"orgCiSecretPut":    {vars: map[string]string{"name": "ORG_SECRET"}, body: map[string]any{"value": "v"}},
	"orgCiSecretDelete": {vars: map[string]string{"name": "ORG_SECRET"}},
	"orgCiVarsList":     {},
	"orgCiVarPut":       {vars: map[string]string{"name": "ORG_VAR"}, body: map[string]any{"value": "v"}},
	"orgCiVarDelete":    {vars: map[string]string{"name": "ORG_VAR"}},
	"runnersList":       {},
	"activityList":      {},
	"insights":          {query: "since=2026-10-01&until=2026-12-01"},
}

// Git operations of the contract that other packages own (their routes are mounted by them).
var gapiElsewhere = map[string]string{
	"codeownersGet": "B8", "autoMergeEnable": "B8", "autoMergeDisable": "B8", "pullReady": "B8",
	"reviewDismiss": "B8", "reviewersRequest": "B8",
	"protectionsList": "A4", "protectionCreate": "A4", "protectionPut": "A4", "protectionDelete": "A4", "protectionEvaluate": "A4",
	"mirrorGet": "C1", "mirrorPut": "C1", "mirrorDelete": "C1", "mirrorSync": "C1",
	"serviceTokensList": "A7", "serviceTokenCreate": "A7", "serviceTokenRevoke": "A7",
	"gitLinkGet": "existing", "gitLinkPut": "existing", "gitLinkDelete": "existing", "gitLinkTest": "existing",
	"previewsList": "existing", "previewsCreate": "existing", "previewsDelete": "existing",
	"notificationsList": "A5", "notificationsMark": "A5", "notifSettingsGet": "A5", "notifSettingsPut": "A5",
}

func gapiExpand(g *gapiRig, def *gapiOp, sp gapiSpec) string {
	vars := map[string]string{
		"orgID": g.org.ID.String(), "projectID": g.proj.ID.String(),
		"n": "1", "sha": g.feature, "branch": "feature", "tag": "v1", "runID": "1", "jobID": "1001",
		"workflowID": "ci.yml", "name": "MY_VAR",
	}
	for k, v := range sp.vars {
		vars[k] = v
	}
	p := def.Path
	for k, v := range vars {
		p = strings.ReplaceAll(p, "{"+k+"}", v)
	}
	if sp.query != "" {
		p += "?" + sp.query
	}
	return p
}

// gapiExpected is what x-permission demands of a role.
func gapiExpected(perm, role string) (status int, allowed bool) {
	switch role {
	case "none":
		return http.StatusForbidden, false
	case "hidden":
		if perm == "org.member" {
			return 0, true
		}
		if perm == "org.admin" {
			return http.StatusForbidden, false
		}
		return http.StatusNotFound, false
	}
	if perm == "org.member" {
		return 0, true
	}
	if perm == "org.admin" {
		return http.StatusForbidden, role == "admin"
	}
	if authz.RoleAllows(authz.Role(role), authz.Action(perm)) {
		return 0, true
	}
	return http.StatusForbidden, false
}

func TestGitAPIContract(t *testing.T) {
	ops := gapiContractOps(t)
	byID := map[string]*gapiOp{}
	for _, d := range ops {
		byID[d.ID] = d
	}

	// 1. every B1 operation exists in the contract and is mounted
	probe := newGapiRig(t, gapiOpts{legacy: true})
	mounted := map[string]bool{}
	for _, r := range probe.routes() {
		mounted[r] = true
	}
	var ids []string
	for id := range gapiB1Ops {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		def := byID[id]
		if def == nil {
			t.Errorf("%s is implemented but missing from the contract", id)
			continue
		}
		if def.Permission == "" {
			t.Errorf("%s declares no x-permission", id)
		}
		if !mounted[def.Method+" "+def.Path] {
			t.Errorf("%s: route %s %s is not mounted", id, def.Method, def.Path)
		}
	}
	// 2. no Git operation is silently left out
	tags := map[string]bool{"Codigo": true, "Ramas": true, "Commits": true, "Pull requests": true, "Actions": true, "Actividad": true}
	for key, def := range ops {
		_ = key
		o := gapiContractDoc["paths"].(map[string]any)[def.Path].(map[string]any)[strings.ToLower(def.Method)].(map[string]any)
		inScope := false
		for _, tg := range o["tags"].([]any) {
			if tags[tg.(string)] {
				inScope = true
			}
		}
		if !inScope {
			continue
		}
		if _, ok := gapiB1Ops[def.ID]; ok {
			continue
		}
		if _, ok := gapiElsewhere[def.ID]; !ok {
			t.Errorf("operation %s (%s %s) is neither implemented by B1 nor assigned to another package", def.ID, def.Method, def.Path)
		}
	}

	// 3. permissions per role, success status and response schema
	roles := []string{"viewer", "deployer", "admin", "hidden", "none"}
	for _, id := range ids {
		id, def, sp := id, byID[id], gapiB1Ops[id]
		if def == nil {
			continue
		}
		t.Run(id, func(t *testing.T) {
			for _, role := range roles {
				opts := gapiOpts{role: role, legacy: id == "repoProvision"}
				if sp.ext {
					opts.core = func(s *gitcore.Service) gitcore.Core { return &gapiExt{Core: s} }
				}
				g := newGapiRig(t, opts)
				var body any
				if sp.body != nil {
					body = sp.body
				}
				rec := g.do(def.Method, gapiExpand(g, def, sp), body)
				wantDeny, allowed := gapiExpected(def.Permission, role)
				if !allowed {
					if rec.Code != wantDeny {
						t.Errorf("%s as %s: status %d, want %d (%s)", id, role, rec.Code, wantDeny, rec.Body.String())
						continue
					}
					var errs []string
					gapiCheckSchema(t, map[string]any{"$ref": "#/components/schemas/Error"}, gapiJSON(t, rec), "$", &errs)
					if len(errs) > 0 {
						t.Errorf("%s as %s: error body drifts from the contract: %v", id, role, errs)
					}
					continue
				}
				if rec.Code == http.StatusForbidden || rec.Code == http.StatusNotFound && sp.skipSuccess == "" {
					t.Errorf("%s as %s: allowed role got %d: %s", id, role, rec.Code, rec.Body.String())
					continue
				}
				if sp.skipSuccess != "" {
					continue
				}
				if rec.Code != def.Success {
					t.Errorf("%s as %s: status %d, want the documented %d: %s", id, role, rec.Code, def.Success, rec.Body.String())
					continue
				}
				if def.SuccessRef != "" {
					var errs []string
					gapiCheckSchema(t, map[string]any{"$ref": def.SuccessRef}, gapiJSON(t, rec), "$", &errs)
					if len(errs) > 0 {
						t.Errorf("%s as %s: response drifts from the contract (%s): %v\n%s", id, role, def.SuccessRef, errs, rec.Body.String())
					}
				}
			}
		})
	}
}

func gapiJSON(t *testing.T, rec *httptest.ResponseRecorder) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("body is not JSON (%d): %q", rec.Code, rec.Body.String())
	}
	return v
}
