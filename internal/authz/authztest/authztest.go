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

// Package authztest starts the dependencies of internal/authz for tests.
package authztest

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

func configureDockerEnv(ctx context.Context) error {
	if os.Getenv("DOCKER_HOST") != "" {
		return nil
	}
	output, err := exec.CommandContext(ctx, "docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}").Output()
	if err != nil {
		return err
	}
	host := strings.TrimSpace(string(output))
	if host == "" {
		return nil
	}
	_ = os.Setenv("DOCKER_HOST", host)
	if os.Getenv("TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE") == "" {
		socket := host
		if runtime.GOOS == "darwin" {
			socket = "/var/run/docker.sock"
		}
		_ = os.Setenv("TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE", socket)
	}
	return nil
}

// StartPostgres starts a PostgreSQL container for the test and returns a pool
// for it. The test is skipped when Docker is unavailable.
func StartPostgres(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	if err := configureDockerEnv(ctx); err != nil {
		t.Skipf("Docker not available for testcontainers: %v", err)
	}
	testcontainers.SkipIfProviderIsNotHealthy(t)

	pgContainer, err := postgres.Run(ctx, "postgres:18-alpine",
		postgres.WithDatabase("authz_test"),
		postgres.WithUsername("authz"),
		postgres.WithPassword("authz"),
	)
	if err != nil {
		t.Fatalf("starting postgres container: %v", err)
	}
	t.Cleanup(func() {
		_ = pgContainer.Terminate(context.Background())
	})

	dsn, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("getting postgres connection string: %v", err)
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("creating pgxpool: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
	})

	var pingErr error
	for i := 0; i < 30; i++ {
		pingErr = pool.Ping(ctx)
		if pingErr == nil {
			return pool
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for postgres ping: %v", pingErr)
	return nil
}
