# AGENTS.md has stale authorization package paths

`AGENTS.md`'s "Control-plane Authorization" bullet says:

> ... against the OpenFGA model in `internal/authz` (`docs/authorization.md`).
> ... A new RPC needs a rule in `cmd/ateapi/internal/rpcauthz`; a test fails
> otherwise.

Both paths are gone. The BasicBlock rebase onto upstream (branch
`basicblock/rebase-2026-10-05`) consolidated the two old packages
(`internal/authz` and `cmd/ateapi/internal/rpcauthz`) into one,
`cmd/ateapi/internal/authz`, during an earlier commit in that rebase (the
"authorization reconciliation"). The model lives at
`cmd/ateapi/internal/authz/model.fga`; a new RPC's rule goes in
`cmd/ateapi/internal/authz/registry.go` (the `defaultRPCPermissions` map).

Caution: AGENTS.md's claim that "a test fails otherwise" is no longer true
in general. `TestAccessPolicyRPCsAlwaysEnforced`
(`cmd/ateapi/internal/authz/interceptor_test.go`) only checks RPCs whose name
contains "AccessPolicy" -- it does not iterate every method in
`Control_ServiceDesc`/`WorkerService_ServiceDesc` and fail on one missing
from `defaultRPCPermissions`. A new RPC with no rule entry currently just
falls through to "denied in enforce mode" silently (confirmed by reading the
interceptor's dispatch: `UnaryServerInterceptor` in
`cmd/ateapi/internal/authz/interceptor.go` does
`rule, registered := defaultRPCPermissions[info.FullMethod]; if !registered ...
{ return handler(ctx, req) }` -- an RPC missing from the map is *allowed*,
not denied, in both audit and enforce mode. Whoever fixes the AGENTS.md
bullet should consider adding a real coverage test (iterate
`Control_ServiceDesc.Methods` and `WorkerService_ServiceDesc.Methods`, fail
on any FullMethodName absent from `defaultRPCPermissions`) rather than just
correcting the path.

I did not edit AGENTS.md (per its own hard rule: only on direct request).
Whoever next touches authorization and notices this should fix the bullet
then, or ask to update it directly.
