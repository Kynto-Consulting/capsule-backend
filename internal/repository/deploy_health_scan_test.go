package repository

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/kynto/capsule/backend/internal/domain"
)

// Every deployment SELECT/RETURNING column list must have exactly as many
// columns as scanRow has destinations (countingRow lives in apitoken_scan_test.go).
func TestDeploymentColumnsMatchScanDestinations(t *testing.T) {
	r := &DeploymentRepository{}
	row := &countingRow{}
	_, _ = r.scanRow(row)
	if row.n == 0 {
		t.Fatal("scanRow did not reach Scan")
	}
	src, err := os.ReadFile("deployment_repo.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?s)(?:SELECT|RETURNING)\s+(id, project_id, server_id.*?error_message)`)
	matches := re.FindAllStringSubmatch(string(src), -1)
	if len(matches) != 5 {
		t.Fatalf("expected 5 deployment column lists, found %d", len(matches))
	}
	for i, m := range matches {
		n := len(strings.Split(m[1], ","))
		if n != row.n {
			t.Errorf("query %d lists %d columns but scanRow scans %d", i, n, row.n)
		}
	}
}

func TestProjectHealthScanDestinations(t *testing.T) {
	row := &countingRow{}
	_, _ = scanProjectHealth(row)
	list := strings.Split(strings.TrimPrefix(projectHealthSelect, "SELECT "), "FROM")[0]
	if cols := len(strings.Split(list, ",")); cols != row.n {
		t.Fatalf("project health select has %d columns, scan has %d", cols, row.n)
	}
}

func TestHealthColsApply(t *testing.T) {
	var d domain.Deployment
	(&deploymentHealthCols{}).apply(&d)
	if d.Health != nil {
		t.Fatal("health must be omitted when never checked")
	}
	now := time.Now()
	(&deploymentHealthCols{status: "healthy", path: "/x", checkedAt: &now, detail: "HTTP 200", errMsg: "boom"}).apply(&d)
	if d.Health == nil || d.Health.Status != "healthy" || d.Health.Path != "/x" || d.ErrorMessage != "boom" {
		t.Fatalf("bad apply: %+v", d)
	}
}
