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

package ingress

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"

	"github.com/agent-substrate/substrate/cmd/atenet/internal/router/extproc"
	"github.com/agent-substrate/substrate/internal/resources"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
)

// AccessMode is what the gateway does with a client that may not reach the
// actor it addresses.
type AccessMode string

const (
	// AccessDisabled forwards every request (the default): actors must
	// authenticate their own clients.
	AccessDisabled AccessMode = "disabled"
	// AccessAudit asks ate-api about every request, logs each one it would
	// deny, and forwards it anyway.
	AccessAudit AccessMode = "audit"
	// AccessEnforce answers a request without a token that authenticates with
	// 401 and one whose principal may not connect with 403, before resuming
	// the actor.
	AccessEnforce AccessMode = "enforce"
)

const (
	// DefaultAccessCacheTTL bounds how long an allowed decision is reused for
	// one token and actor, and so how long a revoked binding keeps admitting
	// new requests. An established connection is not re-checked.
	DefaultAccessCacheTTL = time.Minute
	// deniedAccessCacheTTL keeps a client retrying a denied token from
	// reaching ate-api on every request.
	deniedAccessCacheTTL  = 5 * time.Second
	maxAccessCacheEntries = 10000
)

// AccessConfig configures ingress authorization.
type AccessConfig struct {
	Mode AccessMode
	// TokenHeaders name the request headers a client's token may arrive in,
	// in order of precedence; a "Bearer " prefix is removed. An
	// identity-asserting proxy's header (x-goog-iap-jwt-assertion) comes first.
	TokenHeaders []string
	// StripHeaders are removed from every request before it reaches the
	// actor, along with TokenHeaders: credentials the actor must never see,
	// since it could replay them.
	StripHeaders []string
	// CacheTTL is DefaultAccessCacheTTL when zero.
	CacheTTL time.Duration
}

// Validate checks the mode and header names.
func (c AccessConfig) Validate() error {
	switch c.Mode {
	case "", AccessDisabled, AccessAudit, AccessEnforce:
	default:
		return fmt.Errorf("ingress authorization mode %q is not one of disabled, audit or enforce", c.Mode)
	}
	if c.Mode != "" && c.Mode != AccessDisabled && len(c.TokenHeaders) == 0 {
		return fmt.Errorf("ingress authorization %s needs at least one token header", c.Mode)
	}
	for _, h := range append(append([]string{}, c.TokenHeaders...), c.StripHeaders...) {
		if h == "" || strings.ContainsAny(h, " :\t") || strings.HasPrefix(h, ":") {
			return fmt.Errorf("invalid header name %q", h)
		}
	}
	if c.CacheTTL < 0 {
		return fmt.Errorf("ingress authorization cache TTL must not be negative")
	}
	return nil
}

// AccessChecker is the ate-api call the gateway authorizes clients with.
type AccessChecker interface {
	CheckActorAccess(ctx context.Context, in *ateapipb.CheckActorAccessRequest, opts ...grpc.CallOption) (*ateapipb.CheckActorAccessResponse, error)
}

// accessControl authorizes each request's client for its actor through
// ate-api's CheckActorAccess, and removes client credentials.
type accessControl struct {
	cfg     AccessConfig
	checker AccessChecker
	now     func() time.Time

	mu    sync.Mutex
	cache map[[sha256.Size]byte]accessDecision
}

type accessDecision struct {
	allowed   bool
	principal string
	reason    string
	until     time.Time
}

func newAccessControl(cfg AccessConfig, checker AccessChecker) *accessControl {
	if cfg.Mode == "" {
		cfg.Mode = AccessDisabled
	}
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = DefaultAccessCacheTTL
	}
	for i, h := range cfg.TokenHeaders {
		cfg.TokenHeaders[i] = strings.ToLower(h)
	}
	for i, h := range cfg.StripHeaders {
		cfg.StripHeaders[i] = strings.ToLower(h)
	}
	return &accessControl{cfg: cfg, checker: checker, now: time.Now, cache: map[[sha256.Size]byte]accessDecision{}}
}

// removedHeaders are the headers the actor must not receive.
func (a *accessControl) removedHeaders() []string {
	return append(append([]string{}, a.cfg.TokenHeaders...), a.cfg.StripHeaders...)
}

// authorize returns nil when the request may proceed, or the error to answer
// it with.
func (a *accessControl) authorize(ctx context.Context, md *extproc.RequestMetadata, actor resources.ActorRef) error {
	if a.cfg.Mode == AccessDisabled {
		return nil
	}
	token := a.token(md)
	var decision accessDecision
	if token == "" {
		decision = accessDecision{reason: "no token in " + strings.Join(a.cfg.TokenHeaders, ", ")}
	} else {
		var err error
		decision, err = a.decide(ctx, token, actor)
		if err != nil {
			slog.ErrorContext(ctx, "Ingress authorization check failed", slog.Any("actor", actor), slog.Any("err", err))
			if a.cfg.Mode == AccessAudit {
				return nil
			}
			return extproc.WrapReqError(envoy_type.StatusCode_ServiceUnavailable, err, "authorization is unavailable")
		}
	}
	attrs := []any{slog.Any("actor", actor), slog.String("principal", decision.principal), slog.String("reason", decision.reason)}
	switch {
	case decision.allowed:
		return nil
	case a.cfg.Mode == AccessAudit:
		slog.WarnContext(ctx, "Ingress authorization would deny request (audit mode)", attrs...)
		return nil
	case decision.principal == "":
		slog.InfoContext(ctx, "Ingress authorization denied request", attrs...)
		return extproc.NewReqError(envoy_type.StatusCode_Unauthorized, "a token that authenticates to Substrate is required")
	default:
		slog.InfoContext(ctx, "Ingress authorization denied request", attrs...)
		return extproc.NewReqError(envoy_type.StatusCode_Forbidden, "%s may not connect to actor %s", decision.principal, actor)
	}
}

func (a *accessControl) token(md *extproc.RequestMetadata) string {
	for _, h := range a.cfg.TokenHeaders {
		value := strings.TrimSpace(md.Header(h))
		if len(value) > 7 && strings.EqualFold(value[:7], "bearer ") {
			value = strings.TrimSpace(value[7:])
		}
		if value != "" {
			return value
		}
	}
	return ""
}

func (a *accessControl) decide(ctx context.Context, token string, actor resources.ActorRef) (accessDecision, error) {
	key := sha256.Sum256([]byte(actor.String() + "\x00" + token))
	now := a.now()
	a.mu.Lock()
	cached, ok := a.cache[key]
	a.mu.Unlock()
	if ok && now.Before(cached.until) {
		return cached, nil
	}
	resp, err := a.checker.CheckActorAccess(ctx, &ateapipb.CheckActorAccessRequest{
		Actor: &ateapipb.ObjectRef{Atespace: actor.Atespace, Name: actor.Name},
		Token: token,
	})
	if err != nil {
		return accessDecision{}, err
	}
	decision := accessDecision{allowed: resp.GetAllowed(), principal: resp.GetPrincipal(), reason: resp.GetReason()}
	ttl := deniedAccessCacheTTL
	if decision.allowed {
		ttl = a.cfg.CacheTTL
		// Never past the token's own expiry, which ate-api verified.
		if exp, ok := tokenExpiry(token); ok && exp.Sub(now) < ttl {
			ttl = exp.Sub(now)
		}
	}
	decision.until = now.Add(ttl)
	a.mu.Lock()
	if len(a.cache) >= maxAccessCacheEntries {
		for k, d := range a.cache {
			if !now.Before(d.until) {
				delete(a.cache, k)
			}
		}
		if len(a.cache) >= maxAccessCacheEntries {
			clear(a.cache)
		}
	}
	a.cache[key] = decision
	a.mu.Unlock()
	return decision, nil
}

// tokenExpiry reads a JWT's exp claim without verifying it.
func tokenExpiry(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Exp == 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.Exp, 0), true
}
