package fn

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/pkg/crypto"
)

// NewDBResolver builds the resolver of `db:<name>` scopes from the project's databases. The URL uses the internal
// route (host.docker.internal:<published port>) so the data never leaves the server and never crosses the tunnel.
func NewDBResolver(repo domain.DatabaseRepository, secretKey string) DBResolver {
	return func(ctx context.Context, projectID uuid.UUID, name string) (string, error) {
		dbs, err := repo.ListByProject(ctx, projectID)
		if err != nil {
			return "", err
		}
		for _, d := range dbs {
			if d.Name != name {
				continue
			}
			if d.Port == 0 || len(d.CredentialsEnc) == 0 {
				return "", fmt.Errorf("database %s is not ready", name)
			}
			plain, err := crypto.Decrypt(d.CredentialsEnc, secretKey)
			if err != nil {
				return "", err
			}
			var c struct{ Username, Password string }
			if err := json.Unmarshal(plain, &c); err != nil {
				return "", err
			}
			scheme := "postgres"
			if d.Engine == "mysql" {
				scheme = "mysql"
			}
			u := url.URL{Scheme: scheme, User: url.UserPassword(c.Username, c.Password), Host: fmt.Sprintf("host.docker.internal:%d", d.Port), Path: "/" + d.DBName}
			if scheme == "postgres" {
				u.RawQuery = "sslmode=disable"
			}
			return u.String(), nil
		}
		return "", ErrNotFound
	}
}
