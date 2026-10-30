#!/bin/bash
# The broker's realm: one Keycloak client per app kind, all owned by the hub and sharing its one
# callback URL, each stamping its own API audience on access tokens and requiring its own realm
# role; plus test users. Idempotent: dev/k8s/up.sh runs it on every pass (and the docker compose
# measurement stack on every `docker compose up`).
#
# The hub authenticates as every kind's client with assertions signed by its one private key
# (private_key_jwt); Keycloak reads the public key from the hub's JWKS URL. No client secrets.
set -euo pipefail
export KC_OPTS='-Duser.home=/tmp'
hub_public_url="${hub_public_url:-http://localhost:8090}"
hub_internal_url="${hub_internal_url:-http://hub:8090}"
app_kinds="${app_kinds:-inspection billing}"
# Kinds whose edges call their API directly: each site is an organization, and their
# clients run the membership extension (authbroker.keycloak, built into the Keycloak image).
direct_kinds="${direct_kinds:-}"

until $kcadm config credentials --server "$keycloak_url" --realm master \
    --user "$KEYCLOAK_ADMIN" --password "$KEYCLOAK_ADMIN_PASSWORD" >/dev/null 2>&1; do
  echo "waiting for Keycloak"; sleep 2
done

if ! $kcadm get "realms/$realm" >/dev/null 2>&1; then
  echo "creating realm $realm"
  # Refresh tokens rotate and each works once; a replayed one is refused. The realm's SSO
  # lifetimes are the session lifetimes: the hub keeps a session exactly as long as Keycloak's
  # refresh token lives.
  $kcadm create realms -s realm="$realm" -s enabled=true -s sslRequired=NONE \
    -s bruteForceProtected=true -s failureFactor=3 \
    -s accessTokenLifespan=300 -s ssoSessionIdleTimeout=1800 -s ssoSessionMaxLifespan=36000 \
    -s revokeRefreshToken=true -s refreshTokenMaxReuse=0 \
    -s organizationsEnabled=true
fi

for kind in $app_kinds; do
  client="hub-$kind"
  backchannel_url="$hub_internal_url/auth/backchannel-logout/$kind"
  if [[ "$kind" == "${relay_kind:-}" ]]; then backchannel_url="$relay_url"; fi
  if ! $kcadm get roles -r "$realm" --fields name | grep -q "\"$kind-user\""; then
    $kcadm create roles -r "$realm" -s "name=$kind-user"
  fi
  if $kcadm get clients -r "$realm" -q "clientId=$client" --fields clientId | grep -q "$client"; then
    echo "client $client already exists"
    continue
  fi
  echo "creating client $client"
  # Default scopes are in every token whatever the hub asks for, so only basic (subject and
  # session), roles and acr; profile and email are optional, for kinds whose registry entry
  # requests them. Full scope off: tokens carry only the kind's own role.
  $kcadm create clients -r "$realm" -f - <<JSON
{
  "clientId": "$client",
  "name": "Site hub: $kind",
  "clientAuthenticatorType": "client-jwt",
  "publicClient": false,
  "standardFlowEnabled": true,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": false,
  "serviceAccountsEnabled": false,
  "frontchannelLogout": false,
  "fullScopeAllowed": false,
  "defaultClientScopes": ["basic", "roles", "acr"],
  "optionalClientScopes": $(if [[ " $direct_kinds " == *" $kind "* ]]; then echo '["profile", "email", "organization"]'; else echo '["profile", "email"]'; fi),
  "redirectUris": ["$hub_public_url/auth/callback"],
  "attributes": {
    "pkce.code.challenge.method": "S256",
    "post.logout.redirect.uris": "$hub_public_url/broker/logged-out/*",
    "backchannel.logout.url": "$backchannel_url",
    "backchannel.logout.session.required": "true",
    "access.token.lifespan": "70",
    "use.jwks.url": "true",
    "jwks.url": "$hub_internal_url/.well-known/jwks.json",
    "token.endpoint.auth.signing.alg": "ES256"
  },
  "protocolMappers": [
    {
      "name": "$kind-api-audience",
      "protocol": "openid-connect",
      "protocolMapper": "oidc-audience-mapper",
      "config": {
        "included.custom.audience": "$kind-api",
        "access.token.claim": "true",
        "id.token.claim": "false"
      }
    }
  ]
}
JSON
  uuid=$($kcadm get clients -r "$realm" -q "clientId=$client" --fields id | jq -r '.[0].id')
  $kcadm create -r "$realm" "clients/$uuid/scope-mappings/realm" \
    -b "[$($kcadm get -r "$realm" "roles/$kind-user")]"
  if [[ " $direct_kinds " == *" $kind "* ]]; then
    # Marks the client for the membership client policy below.
    $kcadm create -r "$realm" "clients/$uuid/roles" -s name=organization-membership-required
  fi
done

if [[ -n "$direct_kinds" ]]; then
  # Pinned organization claim: an object keyed by alias, with each organization's id and
  # attributes (tenant), so its shape never changes under the APIs.
  scope_id=$($kcadm get client-scopes -r "$realm" | jq -r '.[] | select(.name == "organization") | .id')
  mapper_id=$($kcadm get "client-scopes/$scope_id/protocol-mappers/models" -r "$realm" | jq -r '.[] | select(.name == "organization") | .id')
  # Config values are strings: kcadm's =true would store a JSON boolean, which Keycloak reads
  # as false.
  $kcadm update "client-scopes/$scope_id/protocol-mappers/models/$mapper_id" -r "$realm" \
    -s 'config.addOrganizationAttributes="true"' -s 'config.addOrganizationId="true"' \
    -s 'config."jsonType.label"=JSON' -s 'config.multivalued="true"'
  # The membership extension, applied to every client marked above.
  $kcadm update client-policies/profiles -r "$realm" -f - <<'JSON'
{ "profiles": [ { "name": "organization-membership",
  "description": "Tokens only for members of exactly the requested site",
  "executors": [ { "executor": "organization-membership", "configuration": {} } ] } ] }
JSON
  $kcadm update client-policies/policies -r "$realm" -f - <<'JSON'
{ "policies": [ { "name": "organization-membership", "enabled": true,
  "conditions": [ { "condition": "client-roles", "configuration": { "roles": ["organization-membership-required"] } } ],
  "profiles": ["organization-membership"] } ] }
JSON
fi
bash "$(dirname "$0")/sync_organizations.sh"

# The organization sync's service account: manage-organizations and nothing more, so the one
# component holding Keycloak admin credentials can only create and change organizations.
if [[ -n "${organization_sync_secret:-}" ]]; then
  sync_client=$($kcadm get clients -r "$realm" -q clientId=organization-sync --fields id | jq -r '.[0].id // empty')
  if [[ -z "$sync_client" ]]; then
    echo "creating client organization-sync"
    $kcadm create clients -r "$realm" -s clientId=organization-sync -s publicClient=false \
      -s clientAuthenticatorType=client-secret -s "secret=$organization_sync_secret" \
      -s standardFlowEnabled=false -s directAccessGrantsEnabled=false -s serviceAccountsEnabled=true
    $kcadm add-roles -r "$realm" --uusername service-account-organization-sync --cclientid realm-management \
      --rolename manage-organizations --rolename view-organizations --rolename query-organizations
  else
    $kcadm update -r "$realm" "clients/$sync_client" -s "secret=$organization_sync_secret"
  fi
fi

# Installation admins: per kind with native installations, a realm role that, with membership of
# an installation's organization, lets a user approve a new machine there. The kind's client
# carries it in its tokens.
for kind in ${native_kinds:-}; do
  role="$kind-installation-admin"
  if ! $kcadm get roles -r "$realm" --fields name | grep -q "\"$role\""; then
    $kcadm create roles -r "$realm" -s "name=$role"
    uuid=$($kcadm get clients -r "$realm" -q "clientId=hub-$kind" --fields id | jq -r '.[0].id')
    $kcadm create -r "$realm" "clients/$uuid/scope-mappings/realm" -b "[$($kcadm get -r "$realm" "roles/$role")]"
  fi
done

# The registry admin API's provisioning client: a service account whose access tokens carry the
# admin audience and realm role the hub's admin API requires. Its secret comes from the
# environment and is updated on every run.
if [[ -n "${registry_provisioner_secret:-}" ]]; then
  if ! $kcadm get roles -r "$realm" --fields name | grep -q '"registry-admin"'; then
    $kcadm create roles -r "$realm" -s name=registry-admin
  fi
  provisioner=$($kcadm get clients -r "$realm" -q clientId=registry-provisioner --fields id | jq -r '.[0].id // empty')
  if [[ -z "$provisioner" ]]; then
    echo "creating client registry-provisioner"
    $kcadm create clients -r "$realm" -f - <<JSON
{
  "clientId": "registry-provisioner",
  "name": "Registry provisioning",
  "publicClient": false,
  "clientAuthenticatorType": "client-secret",
  "secret": "$registry_provisioner_secret",
  "standardFlowEnabled": false,
  "directAccessGrantsEnabled": false,
  "serviceAccountsEnabled": true,
  "fullScopeAllowed": false,
  "defaultClientScopes": ["basic", "roles"],
  "optionalClientScopes": [],
  "protocolMappers": [
    {
      "name": "registry-admin-audience",
      "protocol": "openid-connect",
      "protocolMapper": "oidc-audience-mapper",
      "config": {
        "included.custom.audience": "registry-admin",
        "access.token.claim": "true",
        "id.token.claim": "false"
      }
    }
  ]
}
JSON
    provisioner=$($kcadm get clients -r "$realm" -q clientId=registry-provisioner --fields id | jq -r '.[0].id')
    $kcadm create -r "$realm" "clients/$provisioner/scope-mappings/realm" \
      -b "[$($kcadm get -r "$realm" roles/registry-admin)]"
    $kcadm add-roles -r "$realm" --uusername service-account-registry-provisioner --rolename registry-admin
  else
    $kcadm update -r "$realm" "clients/$provisioner" -s "secret=$registry_provisioner_secret"
  fi
fi

# A pool of test users with every kind's role (the realm's brute-force protection locks a user
# who signs in several times within a second, so each e2e sign-in takes its own user), one with
# no role at all, and one with every role but no site. Created over the admin REST API,
# one call per user: kcadm starts a JVM per call.
pool_size=160
admin_token=$(curl -sf "$keycloak_url/realms/master/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=admin-cli \
  -d "username=$KEYCLOAK_ADMIN" -d "password=$KEYCLOAK_ADMIN_PASSWORD" | jq -r .access_token)
api() { # <method> <path> [json body]
  curl -sf -o /dev/null -X "$1" "$keycloak_url/admin/realms/$realm$2" \
    -H "Authorization: Bearer $admin_token" -H 'Content-Type: application/json' ${3:+-d "$3"}
}
create_user() { # <username> <groups as JSON>
  api POST /users "{\"username\": \"$1\", \"email\": \"$1@example.com\", \"firstName\": \"Site\",
    \"lastName\": \"User\", \"enabled\": true, \"emailVerified\": true, \"groups\": $2,
    \"credentials\": [{\"type\": \"password\", \"value\": \"test\", \"temporary\": false}]}"
}
user_id() { # <username>
  curl -sf "$keycloak_url/admin/realms/$realm/users?username=$1&exact=true" \
    -H "Authorization: Bearer $admin_token" | jq -r '.[0].id'
}
organization_id() { # <alias>
  curl -sf "$keycloak_url/admin/realms/$realm/organizations?search=$1&exact=true" \
    -H "Authorization: Bearer $admin_token" | jq -r ".[] | select(.alias == \"$1\") | .id"
}
has_members() { # <organization id>
  [[ "$(curl -sf "$keycloak_url/admin/realms/$realm/organizations/$1/members?max=1" \
    -H "Authorization: Bearer $admin_token" | jq length)" != 0 ]]
}

# The users, once; on later runs only what a new kind adds below.
if $kcadm get users -r "$realm" -q username=test-user-norole -q exact=true --fields username | grep -q norole; then
  echo "test users already exist"
else
  $kcadm create groups -r "$realm" -s name=test-users >/dev/null
  for n in $(seq 1 $pool_size); do
    create_user "test-user-$n" '["/test-users"]'
  done
  create_user test-user-norole '[]'
  create_user test-user-outsider '["/test-users"]'
fi
# An installation admin for the tests: every kind's role from the pool's group, and each native
# kind's installation admin role; its memberships are the tests' to give.
if [[ -n "${native_kinds:-}" ]]; then
  if ! $kcadm get users -r "$realm" -q username=test-installation-admin -q exact=true --fields username | grep -q installation-admin; then
    create_user test-installation-admin '["/test-users"]'
  fi
  for kind in $native_kinds; do
    $kcadm add-roles -r "$realm" --uusername test-installation-admin --rolename "$kind-installation-admin"
  done
fi
# Every kind's role for the pool, including kinds added since the users were made.
for kind in $app_kinds; do
  $kcadm add-roles -r "$realm" --gname test-users --rolename "$kind-user"
done

# Memberships, managed per site, each only once: added while the site's organization has none.
# members_of <predicate> <alias>...: every pool user for whom `predicate n` holds joins each site.
members_of() {
  local predicate=$1 alias org n; shift
  for alias in "$@"; do
    org=$(organization_id "$alias")
    if [[ -z "$org" ]] || has_members "$org"; then continue; fi
    echo "members for $alias"
    for n in $(seq 1 $pool_size); do
      if "$predicate" "$n"; then api POST "/organizations/$org/members" "\"$(user_id "test-user-$n")\""; fi
    done
  done
}
every() { true; }
even() { (( $1 % 2 == 0 )); }
# Every pool user is a member of the inspection installations plant-a, plant-b, plant-limited
# and the native plant-i; of plant-d, and the even ones also of plant-e; and of the native
# installations plant-f, plant-g and plant-h.
if [[ " $direct_kinds " == *" inspection "* ]]; then members_of every plant-a plant-b plant-limited plant-i; fi
if [[ " $direct_kinds " == *" maintenance "* ]]; then
  members_of every plant-d
  members_of even plant-e
fi
if [[ " $direct_kinds " == *" planner "* ]]; then members_of every plant-f plant-g plant-h; fi
echo "site hub clients ready"
