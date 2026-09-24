# ate-api Authorization

`ate-api` authorizes every RPC against the OpenFGA model in
`internal/authz/model.fga`, evaluated by the OpenFGA server it embeds on its
PostgreSQL store. It is configured with the file passed to
`--authorization-config`.

Without that flag, authorization is disabled and every authenticated principal
may call every RPC on every atespace. That includes every workload that can
present a token the configured providers accept: any pod can project a
service account token for the Kubernetes provider's audience, so with
authorization disabled any pod in the cluster controls every actor. Enabling
`enforce` mode is what closes that. Principals and their groups are described
in [Authentication](authentication.md#principals).

## Configuration

```yaml
# audit logs each call the bindings would deny and allows it;
# enforce denies it with PermissionDenied.
mode: enforce
global:
  owners: []            # everything: every atespace and the workers
  viewers: []           # read every atespace; list across atespaces
  atespaceCreators: []  # create atespaces, each owned by its creator
  connectors: []        # can_connect on every actor in every atespace, nothing else
atespaces:
  <name>:               # the atespace need not exist yet
    owners: []
    editors: []
    viewers: []
```

A binding names one principal as `<provider>:<id>`, where the provider is a
JWT provider's name or `mtls` (for example `google:dev@example.com`,
`kubernetes:system:serviceaccount:ns:name`,
`mtls:spiffe://cluster.local/ns/ate-system/sa/atelet`), or a group as
`group:<name>`: `group:authenticated`, `group:<provider>`, or
`group:<provider>/<claim rule>`. Bindings are validated against the
authentication config at startup, so a typo in a provider or rule name fails
the start.

On startup each replica reconciles the bindings into OpenFGA under an advisory
lock: a binding removed from the file is removed from the store. Restart
`ate-api` to apply a change. Nothing else is stored: an actor's or template's
atespace and an atespace's place under the global scope come from the
resource names in each request, and a caller's group memberships from its
authentication, both as contextual tuples.

Creating an atespace records the caller as its `creator`, which owns it;
deleting the atespace removes that record, so a later atespace of the same
name starts unowned. Creator records are not touched by reconciliation.

## Roles

| Relation                                  | Allows                                                                                                                      |
| ----------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| atespace `viewer`                         | Get and list actors, templates, tags and egress policies; get the atespace; use its templates and tags in other atespaces |
| atespace `editor`                         | Also create, update, suspend, pause, resume, revert and delete actors; reach actors' ports through the ingress gateway (`can_connect`); create and delete templates; create, update and delete tags; change egress policies |
| atespace `owner`                          | Also delete the atespace                                                                                                    |
| global `viewer`                           | View every atespace; list actors, templates, tags and atespaces across atespaces                                            |
| global `owner`                            | Own every atespace; workers, worker assignments and actor credential minting                                                |
| global `atespace_creator`                 | Create atespaces                                                                                                            |
| global `connector`                        | Reach actors' ports through the ingress gateway (`can_connect`) in every atespace, including ones created after the binding; nothing else |

Creating an actor needs `editor` in its atespace and `viewer` on the
template's (and a source tag's) atespace, which may be another one. Methods
without a rule are denied in enforce mode. `WorkerService.SetWorkerCapacity`
is authorized by its handler (only atelet, only for its node's workers).

## Substrate's principals

Substrate's components call `ate-api` with pod identity certificates, so bind
them as global owners:

| Component             | Principal                                                   |
| --------------------- | ----------------------------------------------------------- |
| atecontroller         | `mtls:spiffe://cluster.local/ns/ate-system/sa/ate-controller` |
| atenet router         | `mtls:spiffe://cluster.local/ns/ate-system/sa/atenet-router`  |
| atenet egress gateway | `mtls:spiffe://cluster.local/ns/ate-system/sa/atenet-egress`  |
| atelet                | `mtls:spiffe://cluster.local/ns/ate-system/sa/atelet`         |

`kubectl-ate` without `--token-file` sends a token for the
`ate-system/ate-client` service account, the principal
`<kubernetes provider>:system:serviceaccount:ate-system:ate-client`. ateom
and the pod certificate controller do not call `ate-api`.

## Example

```yaml
mode: enforce
global:
  owners:
  - google:admin@example.com
  - kubernetes:system:serviceaccount:ate-system:ate-client
  - mtls:spiffe://cluster.local/ns/ate-system/sa/ate-controller
  - mtls:spiffe://cluster.local/ns/ate-system/sa/atenet-router
  - mtls:spiffe://cluster.local/ns/ate-system/sa/atenet-egress
  - mtls:spiffe://cluster.local/ns/ate-system/sa/atelet
  atespaceCreators:
  - group:google/example       # the domain's users
  connectors:
  - kubernetes:system:serviceaccount:internal-preview:preview-proxy
atespaces:
  templates:
    viewers:
    - group:google/example
  agents:
    editors:
    - kubernetes:system:serviceaccount:agents:runtime
```

Each user can create atespaces and use only those and the shared templates;
the `agents` runtime drives actors in its one atespace and nothing else; the
preview proxy reaches every atespace's actors, including ones created after
the binding, but cannot get, list, create, update, suspend, resume or delete
anything; and a principal with no binding, such as any other pod's service
account, can do nothing. `cmd/ateapi/internal/rpcauthz/testdata` holds a
fuller example that the enforcement tests run.

## Ingress

The atenet router can authorize the clients of actors, not only callers of
ate-api. With `--ingress-authorization=enforce` it takes each request's token
from the first of `--ingress-token-headers` present (default
`ate-authorization`; a `Bearer ` prefix is optional), asks ate-api's
`CheckActorAccess` whether it authenticates and its principal has
`can_connect` on the addressed actor (editor of its atespace, or a global
connector), and only then resumes and routes to the actor. A request without a
token that authenticates is answered 401, and one without access 403. `audit`
logs `Ingress authorization would deny request (audit mode)` and forwards it
anyway. Token headers, and any `--ingress-strip-headers`, are removed before
the request reaches the actor, which could otherwise replay a client's
credential.

In-cluster clients send their own ServiceAccount token (the Kubernetes
provider's audience) in `ate-authorization`. Behind Identity-Aware Proxy, put
`x-goog-iap-jwt-assertion` first and strip the credential clients present to
the proxy:

```
--ingress-authorization=enforce
--ingress-token-headers=x-goog-iap-jwt-assertion,ate-authorization
--ingress-strip-headers=proxy-authorization
```

Only global owners may call `CheckActorAccess`, since the answer reveals
whether a token is valid.

## Rolling out

Start with `mode: audit` and look for `Authorization would deny call (audit
mode)` in `ate-api`'s logs: each names the method, principal, object and
relation. Bind what is missing, then switch to `enforce`. A check that cannot
be evaluated fails the call with `Unavailable` in enforce mode and is allowed
in audit mode.

## Limitations

- Any atespace creator may take any unused name, including one another
  principal expects to use.
- Credential minting and worker RPCs need a global owner. The model's
  node-scoped `can_mint_ateom_actor_credential` is not wired up, so atelet is
  trusted with every actor.
- Listing across atespaces is all or nothing; there is no filtered list.
- Unless the router enforces [ingress authorization](#ingress), anyone who
  can reach it can reach an actor's ports, and actors must authenticate their
  own clients. With it, a decision is cached per token and actor for
  `--ingress-authorization-cache-ttl` (a minute), and an established
  connection, such as a WebSocket, is not re-checked.
- Every call is checked against PostgreSQL; revocation takes effect on the
  next call.
