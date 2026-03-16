package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ApplyMigrations runs all *.up.sql files in lexical order.
func (p *PostgresStore) ApplyMigrations(ctx context.Context, dir string) error {
	if p == nil || p.db == nil {
		return fmt.Errorf("postgres store is not initialized")
	}
	return ApplyMigrations(ctx, p.db, dir)
}

// ApplyMigrations applies migration scripts from directory against db.
func ApplyMigrations(ctx context.Context, db *sql.DB, dir string) error {
	if db == nil {
		return fmt.Errorf("database is not initialized")
	}
	files, err := migrationFiles(dir)
	if err != nil {
		return err
	}

	for _, file := range files {
		query, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", file, err)
		}
		if strings.TrimSpace(string(query)) == "" {
			continue
		}
		if _, err := db.ExecContext(ctx, string(query)); err != nil {
			return fmt.Errorf("apply migration %s: %w", filepath.Base(file), err)
		}
	}
	return nil
}

func migrationFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations dir %s: %w", dir, err)
	}

	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".up.sql") {
			files = append(files, filepath.Join(dir, name))
		}
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, fmt.Errorf("no up migrations found in %s", dir)
	}
	return files, nil
}
