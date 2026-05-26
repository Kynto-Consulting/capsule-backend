package repository

import (
	"context"
	"embed"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var MigrationsFS embed.FS

func NewPool(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parsing database url: %w", err)
	}
	cfg.MaxConns = 25
	cfg.MinConns = 5

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("creating pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging database: %w", err)
	}

	// Auto-run migrations on startup!
	if err := RunMigrations(ctx, pool); err != nil {
		pool.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	return pool, nil
}

func RunMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	// 1. Create schema_migrations table if not exists
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version bigint PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now()
		)
	`)
	if err != nil {
		return fmt.Errorf("creating schema_migrations table: %w", err)
	}

	// 2. Read migration files from embedded FS
	entries, err := MigrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("reading migrations dir: %w", err)
	}

	type migration struct {
		version int
		name    string
		content string
	}
	var migrations []migration

	re := regexp.MustCompile(`^(\d+)_.*\.up\.sql$`)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		matches := re.FindStringSubmatch(entry.Name())
		if len(matches) < 2 {
			continue
		}
		v, err := strconv.Atoi(matches[1])
		if err != nil {
			continue
		}
		content, err := MigrationsFS.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return fmt.Errorf("reading migration file %s: %w", entry.Name(), err)
		}
		migrations = append(migrations, migration{
			version: v,
			name:    entry.Name(),
			content: string(content),
		})
	}

	// 3. Sort migrations by version
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].version < migrations[j].version
	})

	// Map of migration versions to the core tables they create
	tableMap := map[int]string{
		1:  "users",
		2:  "organizations",
		3:  "projects",
		4:  "servers",
		5:  "deployments",
		6:  "databases",
		7:  "domains",
		8:  "env_vars",
		9:  "workers",
		10: "api_tokens",
		11: "platform_settings",
	}

	// 4. Run migrations sequentially
	for _, m := range migrations {
		var exists bool
		err = pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)", m.version).Scan(&exists)
		if err != nil {
			return fmt.Errorf("checking migration %d: %w", m.version, err)
		}
		if exists {
			continue
		}

		// Pre-check if the table for this migration version already exists in the database
		if tblName, ok := tableMap[m.version]; ok {
			var tblExists bool
			err = pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_class WHERE relname = $1 AND relkind = 'r')", tblName).Scan(&tblExists)
			if err == nil && tblExists {
				fmt.Printf("Migration %s: table '%s' already exists. Recording version in schema_migrations.\n", m.name, tblName)
				_, _ = pool.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT (version) DO NOTHING", m.version)
				continue
			}
		}

		fmt.Printf("Applying migration %s...\n", m.name)

		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("beginning tx for migration %d: %w", m.version, err)
		}
		defer tx.Rollback(ctx)

		// Execute migration content
		sqlContent := m.content
		sqlContent = strings.ReplaceAll(sqlContent, "CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ")
		sqlContent = strings.ReplaceAll(sqlContent, "CREATE INDEX ", "CREATE INDEX IF NOT EXISTS ")
		sqlContent = strings.ReplaceAll(sqlContent, "CREATE UNIQUE INDEX ", "CREATE UNIQUE INDEX IF NOT EXISTS ")

		if _, err := tx.Exec(ctx, sqlContent); err != nil {
			return fmt.Errorf("executing migration %s: %w", m.name, err)
		}

		// Record migration
		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT (version) DO NOTHING", m.version); err != nil {
			return fmt.Errorf("recording migration %d: %w", m.version, err)
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("committing migration %d: %w", m.version, err)
		}
		fmt.Printf("Successfully applied migration %s\n", m.name)
	}

	return nil
}

