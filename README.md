# Auth broker, one edge per kind

One sign-in for every kind of application and every site (installation) of each, without an
identity-provider client per site. A central **hub** signs users in and holds their tokens;
one **edge per app kind**, a cloud service like the hub, serves every site of its kind under each
site's own hostname, keeps each browser's session and calls the API. The hub works with any
OpenID Connect provider; Keycloak is the first one with site support.

This is the auth broker (`~/Rust/Executables/auth-broker-v1`) with its edge-per-site replaced by
an edge per kind; see the RFC "One edge per app kind". What changed:

- the registry holds one `edge_public_key` per kind instead of a `public_key` per site;
- an edge reads the registry and picks the site from the request's `Host`;
- a direct kind's sites each name their API in the registry (`api_url`);
- adding a site is a registry entry and a DNS name: no key, no deployment.

## Layout

| Path                                                   | What it is                                                                                                                                                                                                                                                                                                               |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `crates/hub`                                           | the central hub: one provider client per app kind (`private_key_jwt`), sign-in, sessions sealed in Redis, refresh, and either API forwarding or short-lived tokens for edges                                                                                                                                             |
| `crates/edge`                                          | one per app kind, serving every site of the kind under its own hostname: session cookie per site (`__Host-Http-session`), the CSRF header on every call to `/api/*` and `/auth/*` (RFC 10017), requests signed with the kind's Ed25519 key for the site they are for; holds no refresh tokens and no provider credential |
| `crates/common`                                        | what hub and edge share: signing, the registry, cookies, CSRF, PKCE, sealing, header rules, the client's credentials and IP address (`client`, laid out as the Rust BFF's), request ids, metrics, and the identity provider trait                                                                                        |
| `crates/oidc`                                          | standard OpenID Connect: discovery, token verification, back-channel logout tokens                                                                                                                                                                                                                                       |
| `crates/keycloak`                                      | Keycloak as an identity provider (see [Identity providers](#identity-providers))                                                                                                                                                                                                                                         |
| `crates/native-app`                                    | the desktop side of a native installation: sign-in through the system browser with a loopback redirect, and requests signed with the installation's key (a library, and a command-line stand-in for a desktop app)                                                                                                       |
| `crates/registry-store`                                | installations and their keys in Postgres, for installations created by provisioning automation and keys enrolled by the installations themselves: the schema, writes stamped with a commit-ordered version, and the change feed the hub follows                                                                          |
| `crates/test-api`, `crates/test-helpers`, `crates/e2e` | a stand-in API, a Keycloak fault proxy and logout-token recorder, and the end-to-end tests                                                                                                                                                                                                                               |
| `providers/keycloak`                                   | the Keycloak image with the membership extension (`extension/`), its admin-tools image (`config/`), and the realm and organization scripts (`setup/`)                                                                                                                                                                    |
| `dev/`                                                 | local key generation, the registry templates, and the local cluster's scripts (`dev/k8s/`)                                                                                                                                                                                                                               |
| `deploy/`                                              | the local cluster: kind's config, the ingress and certificates (`platform/`), and every service's manifests (`k8s/`)                                                                                                                                                                                                     |
| `perf/`                                                | the capacity measurements and their report, run against the docker compose stack                                                                                                                                                                                                                                         |

Tokens never cross kinds: each kind's client stamps its own API audience on access tokens, the
hub refuses tokens without it, and each kind's API accepts only its own audience.

## Identity providers

The hub and the test API know their provider only through `common::provider::IdentityProvider`;
`IDENTITY_PROVIDER` picks the implementation:

|                                                                  | `oidc` (default)                                                                    | `keycloak`                                                             |
| ---------------------------------------------------------------- | ----------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| Discovery, PKCE, refresh, `private_key_jwt`, back-channel logout | standard                                                                            | standard                                                               |
| Roles                                                            | top-level `roles` claim                                                             | `realm_access.roles`                                                   |
| Site in the token                                                | not supported: kinds behind the hub only                                            | organization per site, scope `organization:<id>`, claim `organization` |
| Token type check                                                 | none in the payload                                                                 | `typ`: `ID`, `Bearer`                                                  |
| Session lifetime                                                 | 1 hour unless refreshed                                                             | `refresh_expires_in`                                                   |
| Sign-out                                                         | revoke the refresh token (RFC 7009), then the provider's logout page in the browser | end the session server to server with the refresh token                |

A kind whose edges call their API directly needs a provider that names sites in tokens;
with one that cannot, the hub refuses to build that kind's client and reports it not ready. A new
provider is one more implementation of the trait, in its own crate.

## Two ways to reach an API

|                      | Through the hub                                                                                      | Directly (auth hub)                                                          |
| -------------------- | ---------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Registry             | `api_upstream` set                                                                                   | no `api_upstream`                                                            |
| `/api/*` at the edge | signed and forwarded to the hub, which adds the bearer token and `x-app-id`, `x-site-id`, `x-tenant` | sent straight to the site's `api_url` with the provider's access token       |
| Tokens at the edge   | none                                                                                                 | access tokens only, in the edge's memory, at most 60 s, per site and session |
| Site in the token    | no; the API trusts the hub's headers                                                                 | yes: the token names it (Keycloak: an organization per site)                 |
| The API checks       | audience                                                                                             | audience, `azp`, exactly its own site                                        |
| Fits                 | central APIs                                                                                         | APIs next to each site, or central ones that must not trust headers          |

## The registry

The hub and every edge read every `*.json` file in `REGISTRY_DIR`: one file per app kind, owned by
that kind's team; mount the same files into both (e.g. one ConfigMap). Changes are picked up within
`REGISTRY_RELOAD_SECS` without a restart. A change that fails validation is refused as a whole and
logged; the hub and the edges keep serving the previous registry. The hub decides what is
allowed; an edge uses the registry only to know which hosts are its sites and where their APIs
are.

```json
{
  "app": {
    "id": "inspection",
    "client_id": "hub-inspection",
    "edge_public_key": "ed25519:…",
    "api_audience": "inspection-api",
    "scopes": "openid profile email",
    "required_role": "inspection-user",
    "login_per_minute": 600
  },
  "sites": [
    {
      "id": "plant-7",
      "origin": "https://plant-7.inspection.example.com",
      "api_url": "https://inspection-api.internal",
      "tenant": "customer2",
      "enabled": true
    }
  ]
}
```

- `scopes`: what every sign-in for the kind requests (default `openid`); must include `openid`,
  never `offline_access`. The browser has no say. A direct kind's sign-ins also request
  `organization:<site id>`.
- `edge_public_key`: the kind's edge key (`edge keygen`); unique across kinds. Requests for the
  kind's sites must be signed with it.
- `client_secret_file`: only for a hub running with `CLIENT_CREDENTIALS=client_secret`.
- Each site's `api_url` is where the kind's edge sends that site's API calls, with an access token
  naming the site: the same central API for every site, as here, or each site's own. This is
  the recommended setup: the hub carries no API traffic. The kind's `max_concurrency` then
  limits each site's calls in flight on each edge instance; past it, after a 2-second wait, the
  edge answers 503 instead of queueing without bound.
- `api_upstream` instead of `api_url` makes the hub forward the kind's API calls (with
  `api_read_timeout_secs` and `max_concurrency` limiting them), the option a kind can still
  choose; its sites then have no `api_url`.
- `origin`: one hostname per site, pointing at the kind's edge. The edge tells sites apart by it,
  so each site keeps its own cookies.
- `native` lets the kind have desktop-app installations (see
  [Native installations](#native-installations)): each lists its own `keys` instead of an
  `origin`, and `native.redirect_path` (default `/callback`) is its app's loopback path. A kind
  has `edge_public_key`, `native` or both: with both, each installation is a web app (an
  `origin`) or a desktop app (`keys`), all under the kind's one Keycloak client.

Check a change before submitting it: `hub validate-registry <dir>`.

The hub and every edge hold the registry in memory, indexed: finding an installation and checking
a request's signature cost the same at a million installations as at ten. An edge validates the
whole set, as the hub does, but keeps only its own kind. Memory and reload time grow with the
registry (about 76 MB and 0.2 s at 100,000 installations); measure them with
`cargo run --release -p common --example registry_scale --features alloc-stats`.

## Native installations

An installation that is a desktop app on the customer's premises is **native**: its app signs
users in through the hub, and Keycloak has one client per kind, never one per installation
(RFC 8252, OAuth 2.0 for Native Apps). A kind may have native installations only, or alongside
web-app installations served by its edge.

```json
{ "app": { "id": "planner", "client_id": "hub-planner", "native": { "redirect_path": "/callback" },
           "api_audience": "planner-api" },
  "sites": [ { "id": "plant-f", "keys": ["ed25519:…", "ed25519:…"], "api_url": "https://api.plant-f.example",
               "tenant": "customer6" } ] }
```

1. The desktop app listens on `127.0.0.1` at a free port and opens the system browser at
   `{hub}/broker/login?site=plant-f&redirect_uri=http://127.0.0.1:<port>/callback&state=…&code_challenge=…`.
2. The hub accepts only a loopback redirect with the kind's path (any port; never `localhost`),
   signs the user in with the kind's client and the installation's organization, keeps the
   refresh token, and sends the browser back to the loopback address with a one-time code.
3. The app redeems the code with its PKCE verifier at `/broker/redeem`, in a request signed with
   the installation's key, and keeps the session handle it gets; then it fetches short-lived
   access tokens from `/broker/token` the same way, for its API.

Every request is signed with the installation's own Ed25519 key, so the hub knows which
installation is calling; an installation may list several keys, e.g. one per workstation. A
request names its key in `x-site-key-id` (the first 16 characters of the key's base64url
SHA-256), so the hub checks one key however many the installation has, and turns away an
unknown one without a signature check. The kind's edge key never speaks for a native
installation, nor an installation's key for a web-app one.
`native-app keygen <installation> <key file>` makes a key and prints its registry entry.
Retiring an installation (`"enabled": false`) or removing a key refuses its next request.

In the local cluster, the native kind `planner` has the installations `plant-f` (two
workstation keys), `plant-g` and the retired `plant-h`, with their API at
`http://localhost:8185`; and the mixed kind `inspection` has, beside its web-app
installations, the native `plant-i`, with its API at `http://localhost:8181`. Their keys are in
`dev/keys/installation-*.key`. To sign in through your
own browser:

```
NATIVE_HUB_URL=https://hub.broker.localhost NATIVE_HUB_ADDR=127.0.0.1:443 \
NATIVE_SITE_ID=plant-f NATIVE_KEY_FILE=dev/keys/installation-plant-f.key \
  cargo run -p native-app -- sign-in
cargo run -p native-app -- call http://localhost:8185/reports
cargo run -p native-app -- sign-out
```

## Installations in a store

When installations are created by provisioning automation and desktop installations enroll
their own workstation keys, installations and keys live in Postgres (`crates/registry-store`)
instead of the registry files; the files keep the app kinds, which stay few and reviewed. Set
`REGISTRY_DATABASE_URL` on the hub; give the hub and the edges a registry directory whose kind
documents list no sites.

- **The hub serves from memory and follows the store.** It loads every installation at start,
  then every `REGISTRY_SYNC_MILLIS` applies only what changed. If the store is down, it keeps
  serving what it has; no request waits on Postgres.
- **Edges never reach the store.** With `REGISTRY_FROM_HUB=true`, an edge fetches its kind's
  web-app installations from the hub's `GET /broker/registry?since=<version>`, signed with the
  kind's key, then only the changes.
- **The rules are constraints.** Ids, origins, each kind's hosts and every key are unique on every
  write; a removed installation's id and a revoked key never come back.
- **Changes are ordered.** Every write takes the next version from one row and stamps its rows
  with it, so a follower that has seen version N has seen everything before it.

The admin API (`ADMIN_ADDR`, for provisioning; a bearer token from the identity provider with
`ADMIN_AUDIENCE` and `ADMIN_ROLE`):

| Request                                         | Does                                                                                        |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `PUT /admin/installations/{id}`                 | creates or changes an installation: `kind`, `tenant`, `origin` or none, `apiUrl`, `enabled` |
| `GET /admin/installations/{id}`                 | the installation as stored, with every key it ever had                                      |
| `DELETE /admin/installations/{id}`              | removes it for good                                                                         |
| `POST /admin/installations/{id}/keys`           | adds a key (`publicKey`) to a native installation                                           |
| `DELETE /admin/installations/{id}/keys/{keyId}` | revokes a key                                                                               |

A native installation also manages its own keys, in requests signed with a key it holds:
`POST /broker/keys` enrolls another (a new workstation; `native-app enroll <key file>`) and
`DELETE /broker/keys/{keyId}` revokes one (`native-app revoke-key <key id>`). The store checks the
signing key is still in use, so a revoked key never changes keys; for sign-ins and tokens, a
revocation takes effect once each hub has followed it, within `REGISTRY_SYNC_MILLIS`.

Seed a store from registry files with `hub import-registry <dir>`. The local cluster runs this
way: its store is seeded from `dev/registry`, and the tests provision through
`https://registry.broker.localhost` with Keycloak's `registry-provisioner` client. Measure the
store at a million installations with the `store_scale` example in `crates/registry-store`.

## Hub settings

| Variable                                     | Default          | Meaning                                                                                                                          |
| -------------------------------------------- | ---------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `IDENTITY_PROVIDER`                          | `oidc`           | `oidc` or `keycloak`; see [Identity providers](#identity-providers)                                                              |
| `ISSUER_URI`                                 |                  | the realm as tokens name it                                                                                                      |
| `DISCOVERY_URI`                              | `ISSUER_URI`     | where the hub reaches the provider itself, if not at the issuer; only the docker compose measurement stack needs it              |
| `HUB_PUBLIC_URL`                             |                  | the browser-facing address; the one callback derives from it                                                                     |
| `CLIENT_CREDENTIALS`                         | `client_secret`  | `private_key_jwt` (preferred) or `client_secret`                                                                                 |
| `CLIENT_KEY_FILE`, `CLIENT_KEY_ID`           |                  | the hub's EC P-256 key (PEM) and its `kid` (default: thumbprint)                                                                 |
| `CLIENT_NEXT_KEY_FILE`, `CLIENT_NEXT_KEY_ID` |                  | a key published ahead of a rotation                                                                                              |
| `REDIS_URI`                                  |                  | sessions, sign-ins, handoffs, nonces, rate counters                                                                              |
| `REGISTRY_DIR`, `REGISTRY_RELOAD_SECS`       | `10`             | the team files                                                                                                                   |
| `LOGIN_PER_MINUTE_PER_IP`                    | `30`             | sign-in starts per client IP                                                                                                     |
| `CLIENT_IP_HEADER`, `TRUSTED_PROXIES`        |                  | a reverse proxy's client IP header, believed only from these ranges                                                              |
| `MAX_CLOCK_SKEW_SECS`                        | `30`             | how far an edge's clock may drift                                                                                                |
| `SERVED_ACCESS`                              | `web,native`     | the installation access types this deployment serves; installations of another type are refused as unknown                       |
| `REGISTRY_DATABASE_URL`                      |                  | the registry store (Postgres); the files then hold the app kinds only. See [Installations in a store](#installations-in-a-store) |
| `REGISTRY_SYNC_MILLIS`                       | `1000`           | how often the hub follows the store's changes                                                                                    |
| `ADMIN_ADDR`                                 |                  | the registry admin API's address, apart from the public port; only with a store                                                  |
| `ADMIN_AUDIENCE`, `ADMIN_ROLE`               | `registry-admin` | the audience and realm role a provisioning client's access token must carry                                                      |
| `LISTEN_ADDR`                                | `0.0.0.0:8090`   | public address                                                                                                                   |
| `METRICS_ADDR`                               | `0.0.0.0:9100`   | Prometheus metrics, apart from the public port (feature `metrics`)                                                               |
| `ALLOW_INSECURE_HTTP`                        | `false`          | `true` accepts `http://` URLs; local stacks only                                                                                 |

The hub publishes its public client key at `/.well-known/jwks.json`; every kind's provider
client reads it from there. Rotation: set `CLIENT_NEXT_KEY_FILE` and restart (both keys
published, the old one signs); once the provider has the new key set, make it `CLIENT_KEY_FILE`.

Sessions last as long as the provider's: each sign-in and refresh stores the session for as long
as the provider says (Keycloak: `refresh_expires_in`; otherwise an hour), only a refresh extends it, and the hub ends every session 24 hours after
sign-in. Only a 400 or 401 from the provider ends a session on refresh; a 5xx answers 502 and keeps
it. Sign-out follows the provider: server to server with the refresh token for Keycloak,
revocation and the provider's logout page otherwise. A provider need not publish a revocation or
logout endpoint; the step that needs one is then skipped and logged.

## Adding a site

A site needs no key and no deployment of its own: it is one registry entry, a hostname, and for
a direct kind an organization and its members. The kind's edge starts serving it within a
reload interval.

```
kind's team                          hub and the kind's edge          Keycloak
───────────                          ───────────────────────          ────────
1. hostname → the kind's edge (DNS, certificate)
2. entry → kind's registry file ───▶ 3. both reload the registry
                                        (≤ REGISTRY_RELOAD_SECS)
                                     4. direct kinds: sync job ─────▶ organization <site id>
                                                                      5. add the users as members
6. check: hub lists the site, a test sign-in at the site's hostname works
```

### 1. The site's hostname

Point the site's hostname, e.g. `plant-7.inspection.example.com`, at the kind's edge, with a
TLS certificate for it (a wildcard such as `*.inspection.example.com` covers every site of the
kind). Whatever terminates TLS in front of the edge must pass the `Host` header through
unchanged: the edge picks the site by it, and answers 404 for any host that is not one of its
kind's enabled sites.

### 2. The registry entry

Add the site to the `sites` list in the kind's file, ideally through a reviewed change, and check
it first with `hub validate-registry <registry dir>`:

```json
{ "id": "plant-7", "origin": "https://plant-7.inspection.example.com",
  "tenant": "customer2", "enabled": true }
```

- `id`: unique across all kinds; lowercase letters, digits and `-`. For a direct kind it is also
  the organization's alias, which never changes.
- `origin`: the hostname from step 1, `https://` (plain `http://` only for `localhost`).
- `tenant`: the customer; APIs scope data by it.
- `api_url`: a direct kind's site's API, which the edge must be able to reach.

### 3. The hub and the edge pick it up

Every hub and edge instance re-reads the directory within `REGISTRY_RELOAD_SECS` (default 10)
and switches to the new version without a restart. A file that fails validation is refused as a
whole and logged; both keep serving the previous registry, so a typo never takes other sites
down. `GET /health/registry` on the hub shows each instance's registry version and its sites.

### 4–5. Direct kinds only: the site's organization and members

Run the organization sync (`providers/keycloak/setup/sync_organizations.sh`; in the local cluster
`kubectl --context kind-auth-broker -n auth-broker create job sync-now --from=cronjob/organization-sync`,
in production a scheduled job). It creates the organization `plant-7` with the `tenant` attribute and reports
drift. Then add the users who may use the site as members of that organization. A user who is
not a member cannot sign in there: Keycloak and the hub both refuse.

### 6. Check it

- The hub's `GET /health/registry` lists `plant-7` under its kind.
- A test sign-in at `https://plant-7.inspection.example.com/auth/login` ends with the session
  cookie; `GET /auth/session` then names the site and tenant. A 404 there means the edge has not
  loaded the entry yet, or the `Host` header does not reach it unchanged.

### Retiring a site

Set `"enabled": false`: the edge answers 404 for its host and the hub refuses requests for it
within a reload interval, and for a direct kind the next sync disables its organization, so
Keycloak refuses its tokens at the next refresh.

## Adding an app kind

1. Make the kind's edge key, on a machine you trust, with the edge image (or
   `cargo run -p edge --`):

   ```
   docker run --rm --user "$(id -u)" -v "$PWD:/out" auth-broker-kind-edge:dev \
     edge keygen inspection /out/edge-inspection.key
   ```

   It writes the private key (mode 0600) and prints the `edge_public_key` for the kind's
   registry file. Keep the private key in the cloud's secret store; only the edge mounts it.
2. At the identity provider, create a confidential client for the kind (e.g. `hub-inspection`)
   with:
   - client authentication by signed JWT (`private_key_jwt`), ES256, JWKS URL
     `{hub}/.well-known/jwks.json`
   - redirect URI `{HUB_PUBLIC_URL}/auth/callback` (the same for every kind)
   - post-logout redirect `{HUB_PUBLIC_URL}/broker/logged-out/*`
   - PKCE S256 required
   - back-channel logout URL `{hub}/auth/backchannel-logout/{kind}`, session required
   - only the kind's roles in its tokens, and the kind's API audience on access tokens

   In Keycloak: client authenticator "Signed JWT", "full scope allowed" off with the kind's role
   mapped, default scopes `basic`, `roles`, `acr`, an audience mapper, and for a direct kind the
   `organization` client scope as optional plus the client role
   `organization-membership-required`, which applies the membership extension.
   `providers/keycloak/setup/setup_realm.sh` does exactly this for the local stack, with
   refresh-token rotation on (`revokeRefreshToken`, `refreshTokenMaxReuse=0`).
3. Add the kind's registry file with its `edge_public_key`. The hub builds the client within a
   reload interval.
4. Deploy the kind's edge, with as many instances as its traffic needs (they share nothing but
   the registry and the key):

   ```env
   APP_ID=inspection
   EDGE_KEY_FILE=/run/secrets/edge.key
   REGISTRY_DIR=/etc/edge/registry
   # The hub as browsers reach it. With split-horizon DNS the edge reaches it there too; only
   # if it cannot, set HUB_INTERNAL_URL, e.g. http://hub.auth.svc:8090.
   HUB_URL=https://auth.example.com
   # Behind a load balancer: its client IP header and its addresses.
   CLIENT_IP_HEADER=x-real-ip
   TRUSTED_PROXIES=10.0.0.0/8
   ```

   The edge refuses to start if its key is not the kind's `edge_public_key` in the registry. Its
   `GET /health/ready` answers 200 once the hub is reachable and the kind has an enabled site.
5. Make the kind's API accept only access tokens whose audience is its `api_audience`, and for a
   direct kind whose `azp` is the kind's client and which name exactly the site it serves.

### Rotating a kind's edge key

Run `keygen` again, replace `edge_public_key` in the kind's file, and replace the edge's key file
right after the hub has reloaded: requests signed with the old key are refused from then on.

### Edge settings

| Variable                               | Default        | Meaning                                                                                 |
| -------------------------------------- | -------------- | --------------------------------------------------------------------------------------- |
| `APP_ID`                               |                | the app kind whose sites this edge serves                                               |
| `EDGE_KEY_FILE` or `EDGE_KEY`          |                | the kind's Ed25519 private key (base64url PKCS#8)                                       |
| `REGISTRY_DIR`, `REGISTRY_RELOAD_SECS` | `10`           | the registry files, the same the hub reads                                              |
| `REGISTRY_FROM_HUB`                    | `false`        | `true`: the kind's installations come from the hub (its store); the files hold the kind |
| `REGISTRY_SYNC_MILLIS`                 | `1000`         | how often to ask the hub for changes, with `REGISTRY_FROM_HUB`                          |
| `HUB_URL`, `HUB_INTERNAL_URL`          | `HUB_URL`      | the hub as browsers reach it, and as the edge does                                      |
| `API_READ_TIMEOUT_SECS`                | `60`           | direct kinds: longest silence from a site's API                                         |
| `CLIENT_IP_HEADER`, `TRUSTED_PROXIES`  |                | a load balancer's client IP header, believed only from these ranges                     |
| `LISTEN_ADDR`                          | `0.0.0.0:5200` | address and port                                                                        |
| `METRICS_ADDR`                         | `0.0.0.0:9100` | Prometheus metrics, apart from the public port (feature `metrics`)                      |
| `ALLOW_INSECURE_HTTP`                  | `false`        | `true` accepts `http://` URLs; local stacks only                                        |

## Measuring capacity

`perf/` holds the load test's method, its last results and what they mean for capacity
([`perf/REPORT.md`](perf/REPORT.md)); [`perf/README.md`](perf/README.md) says how to run it.

## Requirements

- Browsers can reach the hub and the provider during sign-in.
- Edges reach the hub over HTTPS with paths unchanged, and keep their clocks within 30 seconds
  of the hub's (`MAX_CLOCK_SKEW_SECS`).
- Each site's hostname reaches its kind's edge with the `Host` header unchanged.
- Each site's app sends `x-csrf: 1` on every call to `/api/*` and `/auth/*`, reads included
  (RFC 10017 §6.1.3.3.2): a kind's sites share its domain, so `SameSite` does not keep one
  site's page from sending another site's session cookie. Sign-in (`/auth/login`) and the
  hand-back from the hub (`/auth/handoff`) are navigations and need none. The edge's demo page
  (`crates/edge/static/index.html`) shows how.
- For a direct kind, the edge can reach every site's `api_url`; for sites on customer premises
  that means a published endpoint or a tunnel into each customer's network.
- For kinds through the hub, only the hub can reach their APIs: they trust its `x-app-id`,
  `x-site-id` and `x-tenant` headers.

## Running it locally

The stack runs in a local Kubernetes cluster (kind), as close to production as a laptop allows:
an ingress terminating TLS with certificates from a local CA, one public address per service
that browsers and pods share, and secrets generated on each machine, never committed.

Once per machine:

```
brew install kind helm mkcert nss
mkcert -install        # a local CA, trusted by macOS, Chrome, Safari and Firefox
```

Then, from the workspace root:

```
dev/k8s/up.sh          # creates or updates the cluster; safe to rerun
cargo test -p e2e --features e2e
dev/k8s/down.sh        # deletes the cluster
```

`up.sh` creates your keys and the registry from them on its first run
(`dev/generate-dev-keys.sh`; all ignored by git), builds the images, and prints the addresses.
Every public name is under `broker.localhost`, which Chrome, Firefox and curl resolve to this
machine by themselves (Safari does not), so no hosts-file entries are needed:

| Name                                                                   | What                                                                                                                                    |
| ---------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `https://keycloak.broker.localhost`                                    | Keycloak, realm `broker` (users `test-user-1` … `test-user-160`, password `test`); the admin password is in the `keycloak-admin` secret |
| `https://hub.broker.localhost`                                         | the hub                                                                                                                                 |
| `https://plant-a.inspection.broker.localhost`, `plant-b.inspection…`   | inspection sites; their edge calls the one central inspection API                                                                       |
| `https://plant-c.billing.broker.localhost`                             | the billing site; its kind keeps the hub forwarding its API calls, so that option stays tested                                          |
| `https://plant-d.maintenance.broker.localhost`, `plant-e.maintenance…` | maintenance sites; their edge calls each site's own API                                                                                 |

- **One wildcard certificate per kind**, as the RFC describes: each edge's ingress serves
  `*.<kind>.broker.localhost`.
- **One address for Keycloak and the hub**: pods reach `https://keycloak.broker.localhost` and
  `https://hub.broker.localhost` through the ingress too (CoreDNS rewrites the names), so the
  issuer and the hub's address are the same for browsers and services. The edges need no
  `HUB_INTERNAL_URL`.
- **The registry**: the hub and the edges read the app kinds from this checkout's
  `dev/registry/kinds` (the nodes see `dev/registry` at `/registry`), and the installations from
  the registry store, a PostgreSQL seeded from `dev/registry` on every `up.sh`. A changed kind
  file reaches them within seconds, a store change within a second. The cluster is tied to this
  checkout's path; recreate it after moving the checkout.
- **Test helpers**: a proxy in front of Keycloak that tests can make fail, answering at
  Keycloak's own address for the hub only, and a recorder of back-channel logout tokens. The
  tests reach Redis, the hub's metrics, the helpers and the stand-in APIs on `127.0.0.1`
  ports 6380, 8091, 5290 and 8181–8185.
- **The organization sync** is a suspended CronJob; run it with
  `kubectl --context kind-auth-broker -n auth-broker create job sync-now --from=cronjob/organization-sync`.

The cluster uses ports 80 and 443, like `auth-api`'s cluster: run one at a time.

### The measurement stack

`docker-compose.yml` (with `docker-compose.perf.yml`) is now only the stack the capacity
measurements in `perf/` run against: it reads each container's CPU from Docker. It uses the
registry in `dev/registry-compose`, with `http://<site>.localhost:<port>` origins, and Keycloak
at two addresses (`DISCOVERY_URI`), which the hub keeps supporting for it.
