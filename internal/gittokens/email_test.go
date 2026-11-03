package gittokens

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestAliasEmail(t *testing.T) {
	id := uuid.MustParse("9e26fda1-2983-40c0-a5eb-3876e2e92cfd")
	got := AliasEmail("palarcon@tumi-ai.com", id)
	if !strings.HasPrefix(got, "palarcon+git") || !strings.HasSuffix(got, "@tumi-ai.com") {
		t.Fatalf("unexpected alias %q", got)
	}
	if got != AliasEmail("palarcon@tumi-ai.com", id) {
		t.Fatal("alias must be stable")
	}
	if AliasEmail("palarcon+old@tumi-ai.com", id) != got {
		t.Fatal("an existing +tag must be replaced, not stacked")
	}
	if AliasEmail("no-at-sign", id) != "" || AliasEmail("@x.com", id) != "" {
		t.Fatal("malformed addresses must give no alias")
	}
}
