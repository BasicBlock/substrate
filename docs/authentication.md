# ate-api Authentication

`ate-api` accepts mTLS client certificates and bearer JWTs. JWT providers are
configured with the file passed to `--authentication-config`:

```yaml
actorIdentityJWTProvider: kubernetes
jwtProviders:
- name: kubernetes
  issuer: https://kubernetes.default.svc.cluster.local
  audiences:
  - api.ate-system.svc
  certificateAuthorityFile: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
  discoveryTokenFile: /var/run/secrets/kubernetes.io/serviceaccount/token
- name: google
  issuer: https://accounts.google.com
  audiences:
  - 32555940559.apps.googleusercontent.com
```

Provider names and issuers must be unique. `issuer` must be an HTTPS URL and
`audiences` must be non-empty; a token is accepted when any configured audience
matches. `certificateAuthorityFile` and `discoveryTokenFile` are optional and
are needed for OIDC discovery against some private Kubernetes API servers.

`actorIdentityJWTProvider` identifies the provider allowed to call
`ActorIdentity.MintJWT`.

Authentication only establishes who a caller is. Unless
[authorization](authorization.md) is enforced, every authenticated principal
controls the entire control plane: every atespace, actor, actor template,
egress policy, snapshot and worker in the cluster. For the Kubernetes provider
that is every pod, since any pod can project a service account token for the
configured audience.

## Principals

Every authenticated caller is a principal named by its provider and an ID:

| Credential                     | Provider                     | ID                                                                          |
| ------------------------------ | ---------------------------- | --------------------------------------------------------------------------- |
| Client certificate             | `mtls`                       | The first URI SAN, for example `spiffe://cluster.local/ns/ate-system/sa/atelet` |
| Kubernetes service account JWT | the provider's `name`        | `sub`, for example `system:serviceaccount:ate-system:ate-client`            |
| Other JWT                      | the provider's `name`        | the claim named by `principalClaim` (default `sub`)                         |

A principal also belongs to groups: `authenticated`, its provider's name, and
`<provider>/<rule>` for each named claim rule it satisfies.
[Authorization](authorization.md) bindings name principals as
`<provider>:<id>` and groups as `group:<name>`. Provider names therefore may
not contain `:`, `/`, `#`, `%` or spaces, and `mtls` and `authenticated` are
reserved.

### Claim rules

`claimRules` restrict which tokens a provider admits. A token must satisfy at
least one rule; a rule requires exact values for the listed claims (a boolean
or number is written as its JSON text, so `true` matches both `true` and
`"true"`) and, with `principalSuffix`, a principal ending in that suffix. One
issuer can so serve differently constrained principals. Google identity tokens
use `email` as the principal: the subject is an opaque number, and a user's
token carries the Workspace domain in `hd` while a service account's carries no
`hd`:

```yaml
- name: google
  issuer: https://accounts.google.com
  audiences:
  - 32555940559.apps.googleusercontent.com  # gcloud auth print-identity-token
  - api.ate-system.svc                      # service accounts' requested audience
  principalClaim: email
  claimRules:
  - name: example
    claims: {hd: example.com, email_verified: true}
  - name: service-accounts
    claims: {email_verified: true}
    principalSuffix: "@my-project.iam.gserviceaccount.com"
```

Here `dev@example.com` is the principal `google:dev@example.com` in the groups
`google` and `google/example`, and a token for
`runtime@other-project.iam.gserviceaccount.com` or `someone@gmail.com` is
rejected.

## Google Cloud CLI tokens

The Google Cloud CLI currently issues user identity tokens with issuer
`https://accounts.google.com` and audience
`32555940559.apps.googleusercontent.com`, the Cloud SDK's shared client ID.
These values are examples rather than built-in defaults; verify the claims
issued by your identity provider and configure them explicitly.

With the provider configured, pipe the token to `kubectl-ate`:

```sh
gcloud auth print-identity-token | kubectl ate --token-file=- get actors
```

`--token-file` accepts either a file path or `-` for stdin and only replaces the
credential sent to `ate-api`. `kubectl-ate`
still uses kubeconfig access to establish its port-forward and obtain the
server trust bundle.

For a manifest-based installation, replace the authentication ConfigMap and
restart the deployment:

```sh
kubectl -n ate-system create configmap ate-api-authentication \
  --from-file=authentication.yaml \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n ate-system rollout restart deployment/ate-api-server
```

Configuration is read at process startup. Restart `ate-api` pods after changing
the ConfigMap. OIDC signing keys are cached and refreshed when an unknown key ID
is encountered.
