// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package atepg

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

const (
	migrationTableName = "schema_migrations"
	migrationLockName  = "agent-substrate:atepg:migrations"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

func applyMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	// The schema needs PostgreSQL 13+ (xid8, pg_current_xact_id,
	// pg_current_snapshot). Report a clear error before PostgreSQL reports an
	// opaque DDL or function error.
	var version int
	if err := pool.QueryRow(ctx, `SELECT current_setting('server_version_num')::int`).Scan(&version); err != nil {
		return fmt.Errorf("get PostgreSQL version: %w", err)
	}
	if version < 130000 {
		return fmt.Errorf("atepg requires PostgreSQL 13 or newer for xid8 and pg_current_snapshot. server_version_num is %d", version)
	}
	if err := rejectUnversionedSubstrateSchema(ctx, pool); err != nil {
		return err
	}
	if err := adoptOpenFGATables(ctx, pool); err != nil {
		return err
	}

	migrations, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		return fmt.Errorf("open embedded PostgreSQL migrations: %w", err)
	}
	provider, err := openMigrationProvider(ctx, pool, migrations)
	if err != nil {
		return err
	}
	return errors.Join(migrateToLatest(ctx, provider), provider.Close())
}

func openMigrationProvider(ctx context.Context, pool *pgxpool.Pool, migrations fs.FS) (*goose.Provider, error) {
	lockID, err := migrationLockID(ctx, pool)
	if err != nil {
		return nil, err
	}
	locker, err := lock.NewPostgresSessionLocker(
		lock.WithLockID(lockID),
		lock.WithLockTimeout(1, 300),
	)
	if err != nil {
		return nil, fmt.Errorf("create PostgreSQL migration locker: %w", err)
	}
	db := stdlib.OpenDBFromPool(pool)
	provider, err := goose.NewProvider(
		goose.DialectPostgres,
		db,
		migrations,
		goose.WithTableName(migrationTableName),
		goose.WithSessionLocker(locker),
	)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create PostgreSQL migration provider: %w", err)
	}
	return provider, nil
}

func migrationLockID(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	var lockID int64
	if err := pool.QueryRow(ctx, `SELECT hashtextextended($1 || ':' || current_schema(), 0)`, migrationLockName).Scan(&lockID); err != nil {
		return 0, fmt.Errorf("get PostgreSQL migration lock ID: %w", err)
	}
	return lockID, nil
}

// rejectUnversionedSubstrateSchema stops Goose before it creates a migration
// ledger in a database from a pre-migration ateapi version.
// The list contains all tables in the pre-migration schema. Goose creates the
// migration ledger before it creates a later table.
func rejectUnversionedSubstrateSchema(ctx context.Context, pool *pgxpool.Pool) error {
	var hasMetadata, hasSubstrateTables bool
	err := pool.QueryRow(ctx, `
		SELECT
			to_regclass('schema_migrations') IS NOT NULL,
			EXISTS (
				SELECT 1 FROM information_schema.tables
				WHERE table_schema = current_schema()
				AND table_name IN (
					'atespaces', 'actors', 'actor_templates',
					'actor_snapshots', 'actor_snapshot_tags', 'workers',
					'worker_outbox', 'worker_outbox_default',
					'worker_outbox_trim', 'leases'
				)
			)`).Scan(&hasMetadata, &hasSubstrateTables)
	if err != nil {
		return fmt.Errorf("check PostgreSQL migration ledger: %w", err)
	}
	if hasSubstrateTables && !hasMetadata {
		return errors.New("unsupported PostgreSQL schema: Substrate tables exist without a migration ledger")
	}
	return nil
}

const (
	// openFGAMigration is the migration that creates OpenFGA's tables
	// (migrations/000002_openfga.sql).
	openFGAMigration = 2
	// openFGATablesVersion is the OpenFGA PostgreSQL migration version that
	// openFGAMigration ports.
	openFGATablesVersion = 6
)

// adoptOpenFGATables records openFGAMigration as applied in a schema whose
// OpenFGA tables OpenFGA's own embedded migrations already created: ate-api
// ran those, tracked in goose_db_version, until its migrations took the tables
// over. The DDL is the same, and running it again would fail on the existing
// tables, so the adoption keeps them and every authorization tuple in them. It
// holds the migrations' lock, so it cannot race another replica's migration.
func adoptOpenFGATables(ctx context.Context, pool *pgxpool.Pool) error {
	lockID, err := migrationLockID(ctx, pool)
	if err != nil {
		return err
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquiring a connection to adopt OpenFGA tables: %w", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, lockID); err != nil {
		return fmt.Errorf("locking PostgreSQL migrations: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, lockID)
	}()

	var hasLedger, hasTuples, hasOpenFGALedger bool
	if err := conn.QueryRow(ctx, `SELECT
		to_regclass('schema_migrations') IS NOT NULL,
		to_regclass('tuple') IS NOT NULL,
		to_regclass('goose_db_version') IS NOT NULL`).Scan(&hasLedger, &hasTuples, &hasOpenFGALedger); err != nil {
		return fmt.Errorf("checking for OpenFGA tables: %w", err)
	}
	if !hasTuples || !hasLedger {
		// No OpenFGA tables to adopt, or a schema Substrate never migrated,
		// which migration 1 then fails on loudly.
		return nil
	}
	var applied []int64
	if err := conn.QueryRow(ctx, `SELECT COALESCE(array_agg(version_id), '{}'::bigint[]) FROM schema_migrations WHERE is_applied AND version_id IN (1, $1)`, openFGAMigration).Scan(&applied); err != nil {
		return fmt.Errorf("reading PostgreSQL migration versions: %w", err)
	}
	if slices.Contains(applied, openFGAMigration) {
		return nil
	}
	if !slices.Contains(applied, 1) {
		return errors.New("unsupported PostgreSQL schema: OpenFGA tables exist before Substrate's first migration")
	}
	if !hasOpenFGALedger {
		return errors.New("unsupported PostgreSQL schema: OpenFGA tables exist without OpenFGA's migration ledger (goose_db_version)")
	}
	var version int64
	if err := conn.QueryRow(ctx, `SELECT COALESCE(max(version_id), 0) FROM goose_db_version WHERE is_applied`).Scan(&version); err != nil {
		return fmt.Errorf("reading OpenFGA's migration version: %w", err)
	}
	if version != openFGATablesVersion {
		return fmt.Errorf("unsupported PostgreSQL schema: OpenFGA's tables are at its migration %d, but migration %d creates them at %d", version, openFGAMigration, openFGATablesVersion)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO schema_migrations (version_id, is_applied) VALUES ($1, true)`, openFGAMigration); err != nil {
		return fmt.Errorf("recording the adopted OpenFGA tables: %w", err)
	}
	slog.InfoContext(ctx, "Adopted OpenFGA tables created by OpenFGA's own migrations",
		slog.Int("migration", openFGAMigration), slog.Int64("openfga_version", version))
	return nil
}

func migrateToLatest(ctx context.Context, provider *goose.Provider) (migrationErr error) {
	started := time.Now()
	current, latest, err := provider.GetVersions(ctx)
	if err != nil {
		return fmt.Errorf("get PostgreSQL migration versions: %w", err)
	}
	starting := current

	applied := 0
	defer func() {
		attributes := []any{
			slog.Int64("starting_version", starting),
			slog.Int64("current_version", current),
			slog.Int64("latest_version", latest),
			slog.Int("applied_migrations", applied),
			slog.Duration("duration", time.Since(started)),
		}
		if migrationErr != nil {
			attributes = append(attributes, slog.Any("err", migrationErr))
			slog.ErrorContext(ctx, "PostgreSQL migrations failed", attributes...)
			return
		}
		slog.InfoContext(ctx, "PostgreSQL migrations ready", attributes...)
	}()

	results, err := provider.Up(ctx)
	if err != nil {
		var partial *goose.PartialError
		if errors.As(err, &partial) {
			applied = len(partial.Applied)
		}
		applyErr := fmt.Errorf("apply PostgreSQL migrations: %w", err)
		failedCurrent, _, versionErr := provider.GetVersions(ctx)
		if versionErr != nil {
			return errors.Join(applyErr, fmt.Errorf("get PostgreSQL migration versions after a failure: %w", versionErr))
		}
		current = failedCurrent
		return applyErr
	}
	applied = len(results)
	current, _, err = provider.GetVersions(ctx)
	if err != nil {
		return fmt.Errorf("get PostgreSQL migration versions after migration: %w", err)
	}
	return nil
}
