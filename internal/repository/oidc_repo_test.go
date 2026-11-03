package repository

import (
	"strings"
	"testing"

	"github.com/kynto/capsule/backend/internal/oidc"
)

// Every scan must use exactly as many destinations as its SELECT/RETURNING lists
// columns (a mismatch fails every query at runtime).
func TestOIDCScansMatchColumns(t *testing.T) {
	cases := []struct {
		name string
		cols string
		scan func(r oidcRowScanner) error
	}{
		{"client", oauthClientCols, func(r oidcRowScanner) error { return scanOAuthClient(r, &oidc.Client{}) }},
		{"request", oauthRequestCols, func(r oidcRowScanner) error { return scanOAuthRequest(r, &oidc.AuthRequest{}) }},
		{"code", oauthCodeCols, func(r oidcRowScanner) error { return scanOAuthCode(r, &oidc.Code{}) }},
		{"refresh", oauthRefreshCols, func(r oidcRowScanner) error { return scanOAuthRefresh(r, &oidc.RefreshToken{}) }},
		{"orgrole", orgRoleCols, func(r oidcRowScanner) error { return scanOrgRole(r, &oidc.OrgRole{}) }},
	}
	for _, c := range cases {
		row := &countingRow{}
		if err := c.scan(row); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if want := len(strings.Split(c.cols, ",")); row.n != want {
			t.Errorf("%s: scan has %d destinations but columns list has %d", c.name, row.n, want)
		}
	}
}
