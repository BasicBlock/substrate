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

package authz

import (
	"context"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openfga/openfga/pkg/server"
)

// Server is the embedded OpenFGA server the Authorizer checks against, with
// the store and authorization model it provisioned.
type Server struct {
	closeOnce sync.Once
	fgaServer *server.Server
	// pool serializes binding reconciliation across replicas.
	pool    *pgxpool.Pool
	storeID string
	modelID string
}

// NewServer creates the OpenFGA server on pool (NewOpenFGAServer), whose
// schema ate-api's migrations own, and ensures its store and model
// (EnsureStoreAndModel). pool stays the caller's: Close stops OpenFGA without
// closing it.
func NewServer(ctx context.Context, pool *pgxpool.Pool) (*Server, error) {
	fgaServer, err := NewOpenFGAServer(pool)
	if err != nil {
		return nil, err
	}
	storeID, modelID, err := EnsureStoreAndModel(ctx, pool, fgaServer)
	if err != nil {
		fgaServer.Close()
		return nil, err
	}
	return &Server{fgaServer: fgaServer, pool: pool, storeID: storeID, modelID: modelID}, nil
}

// FGAServer returns the underlying OpenFGA server instance.
func (s *Server) FGAServer() *server.Server {
	return s.fgaServer
}

// StoreID returns the active OpenFGA store ID.
func (s *Server) StoreID() string {
	return s.storeID
}

// ModelID returns the active OpenFGA authorization model ID.
func (s *Server) ModelID() string {
	return s.modelID
}

// InTx runs fn with a PostgreSQL transaction on the server's pool in its
// context (ContextWithTx): the datastore reads and writes tuples only inside
// one, so everything fn changes commits together, or not at all.
func (s *Server) InTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return fn(ContextWithTx(ctx, tx))
	})
}

// Close stops the OpenFGA server. It is safe to call more than once.
func (s *Server) Close() {
	s.closeOnce.Do(s.fgaServer.Close)
}
