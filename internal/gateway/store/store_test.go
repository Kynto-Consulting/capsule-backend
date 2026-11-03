package store

import (
	"errors"
	"strings"
	"testing"
)

type countingRow struct{ n int }

func (c *countingRow) Scan(dest ...any) error { c.n = len(dest); return nil }

func colCount(cols string) int { return len(strings.Split(cols, ",")) }

func TestScansMatchColumns(t *testing.T) {
	cases := []struct {
		name string
		cols string
		scan func(r *countingRow) error
	}{
		{"service", serviceCols, func(r *countingRow) error { return scanService(r, &Service{}) }},
		{"access", accessCols, func(r *countingRow) error { return scanAccess(r, &Access{}) }},
		{"route", routeCols, func(r *countingRow) error { return scanRoute(r, &Route{}) }},
		{"routeView", routeViewCols, func(r *countingRow) error { return scanRouteView(r, &RouteView{}) }},
		{"lease", leaseCols, func(r *countingRow) error { return scanLease(r, &Lease{}) }},
		{"leaseView", leaseViewCols, func(r *countingRow) error { return scanLeaseView(r, &LeaseView{}) }},
	}
	for _, c := range cases {
		row := &countingRow{}
		if err := c.scan(row); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if want := colCount(c.cols); row.n != want {
			t.Errorf("%s scans %d destinations but selects %d columns", c.name, row.n, want)
		}
	}
}

func TestValidServiceName(t *testing.T) {
	ok := []string{"db", "api-1", "a", "0", strings.Repeat("a", 63)}
	bad := []string{"", "-a", "a-", "A", "a_b", "a.b", "a b", strings.Repeat("a", 64)}
	for _, n := range ok {
		if !ValidServiceName(n) {
			t.Errorf("%q should be valid", n)
		}
	}
	for _, n := range bad {
		if ValidServiceName(n) {
			t.Errorf("%q should be invalid", n)
		}
	}
}

func TestQuotaErrorIs(t *testing.T) {
	var err error = &QuotaError{Scope: "org", Limit: 20}
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatal("QuotaError must match ErrQuotaExceeded")
	}
	if errors.Is(err, ErrPortPoolExhausted) {
		t.Fatal("QuotaError must not match ErrPortPoolExhausted")
	}
}

func TestMapErrNoRows(t *testing.T) {
	if !errors.Is(mapErr(errNoRows()), ErrNotFound) {
		t.Fatal("pgx.ErrNoRows must map to ErrNotFound")
	}
	if mapErr(nil) != nil {
		t.Fatal("nil must stay nil")
	}
}
