package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/kynto/capsule/backend/internal/access"
	"github.com/kynto/capsule/backend/internal/server/handlers"
)

// Every route MountAccess registers (P4) has a row in routePermissions that is no longer "Planned", and every row still "Planned" is
// not mounted. The enforcement of each row by its handler is proved against Postgres in handlers/access_http_db_test.go.
func TestMountedAccessRoutesMatchTheTable(t *testing.T) {
	handlers.WireAccess(access.New(nil, nil, nil), nil)
	t.Cleanup(func() { handlers.WireAccess(nil, nil) })
	r := chi.NewRouter()
	r.Route("/api/v1", func(r chi.Router) { handlers.MountAccess(r) })
	mounted := map[string]bool{}
	_ = chi.Walk(r, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		mounted[method+" "+route] = true
		return nil
	})
	if len(mounted) < 29 {
		t.Fatalf("MountAccess registered only %d routes", len(mounted))
	}
	for k := range mounted {
		row, ok := routePermissions[k]
		if !ok {
			t.Errorf("mounted route without a row in routePermissions: %s", k)
			continue
		}
		if row.Planned {
			t.Errorf("%s is mounted but its row is still Planned", k)
		}
	}
	for k, row := range routePermissions {
		if row.Planned && mounted[k] {
			t.Errorf("planned row %s is mounted", k)
		}
	}
	// none of the P4 families is left planned
	for k, row := range routePermissions {
		if !row.Planned {
			continue
		}
		for _, fam := range []string{"/templates", "/groups", "/assignments", "/access-audit", "/access/simulate", "/me/permissions", "/permissions/catalog", "/access-override", "/members/{userID}/template"} {
			if strings.Contains(k, fam) && !strings.Contains(k, "group-sources") {
				t.Errorf("a P4 route is still planned: %s", k)
			}
		}
	}
}
