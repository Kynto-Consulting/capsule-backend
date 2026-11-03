package gittokens

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/google/uuid"
)

// EmailResolver is optional on an IdentityResolver: it returns the address Forgejo registers for a
// user's account the first time they authenticate with a cgt_ token (the account is created by
// reverse-proxy auto-registration, which would otherwise invent <uuid>@localhost).
type EmailResolver interface {
	ForgejoEmail(ctx context.Context, userID uuid.UUID) (string, error)
}

// AliasEmail turns a Capsule address into a stable sub-address of the same mailbox:
// palarcon@tumi-ai.com -> palarcon+git3fa2c1@tumi-ai.com. The suffix keeps the Forgejo address
// unique and distinct from the OIDC one while mail still reaches the person.
func AliasEmail(email string, userID uuid.UUID) string {
	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 {
		return ""
	}
	local, domain := email[:at], email[at+1:]
	if i := strings.Index(local, "+"); i >= 0 {
		local = local[:i]
	}
	sum := sha256.Sum256([]byte(userID.String()))
	return local + "+git" + hex.EncodeToString(sum[:3]) + "@" + domain
}

func (s *Service) emailFor(ctx context.Context, tok *Token) string {
	if tok == nil || tok.Kind == KindService {
		return ""
	}
	er, ok := s.d.Identity.(EmailResolver)
	if !ok {
		return ""
	}
	k := "mail|" + tok.UserID.String()
	if v, ok := s.vc.getLogin(k); ok {
		return v
	}
	v, err := er.ForgejoEmail(ctx, tok.UserID)
	if err != nil {
		return ""
	}
	s.vc.putLogin(k, v)
	return v
}
