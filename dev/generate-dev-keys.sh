#!/usr/bin/env bash
# Creates the local stack's private keys, next to this script, and the registry files that
# hold their public halves. Each developer generates their own; none of it is committed.
#
#   keys/hub-client-key.pem   the hub's client key (EC P-256): Keycloak checks the hub's client
#                             assertions against its public half, read from the hub's JWKS URL
#   keys/edge-<kind>.key      each app kind's edge key (Ed25519): one edge serves all the kind's
#                             sites
#   keys/installation-<id>.key  each native installation's key (Ed25519), for its desktop app;
#                             an installation may list several, e.g. one per workstation
#   registry/*.json           registry-templates/*.json with each kind's edge public key and its
#                             sites' origins in the local cluster (https://<site>.<kind>.broker.localhost)
#   registry-compose/*.json   the same with the docker compose stack's origins
#                             (http://<site>.localhost:<the kind's edge port>), for perf/
#
#   dev/generate-dev-keys.sh            # creates what is missing
#   dev/generate-dev-keys.sh --force    # replaces every key
# Restart the stack after replacing keys.
set -euo pipefail

dev="$(cd "$(dirname "$0")" && pwd)"
force="${1:-}"
mkdir -p "$dev/keys" "$dev/registry" "$dev/registry-compose"

# Readable by the containers' own user. Local test keys only: production keys come from a
# secret store.
write_key() { # <file> <command producing the key>
  local file=$1; shift
  if [[ -e "$file" && "$force" != "--force" ]]; then return; fi
  "$@" > "$file.tmp"
  chmod 644 "$file.tmp"
  mv "$file.tmp" "$file"
  echo "Created $file"
}

base64url() { base64 | tr '+/' '-_' | tr -d '=\n'; }

hub_key() { openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt; }
# PKCS#8 DER in base64url, as EDGE_KEY_FILE expects.
edge_key() { openssl genpkey -algorithm ed25519 -outform DER | base64url; }
# The registry's edge_public_key: the raw 32-byte Ed25519 public key, base64url.
edge_public_key() {
  base64 -d <<<"$(tr -- '-_' '+/' < "$1" | sed -e 's/$/===/' -e 's/^\(\(....\)*\).*/\1/')" \
    | openssl pkey -inform DER -pubout -outform DER | tail -c 32 | base64url
}

write_key "$dev/keys/hub-client-key.pem" hub_key

# Edge keys and native installations' keys, named by their placeholders in the templates.
edges=$(grep -ho '"@\(edge\|installation\)-[a-z0-9-]*@"' "$dev"/registry-templates/*.json | tr -d '"@' | sort -u)
for edge in $edges; do
  write_key "$dev/keys/$edge.key" edge_key
done

# Each kind's edge port in the docker compose stack.
compose_port() {
  case "$1" in
    inspection) echo 5201 ;;
    billing) echo 5202 ;;
    maintenance) echo 5203 ;;
    *) echo "no compose port for kind $1" >&2; exit 1 ;;
  esac
}

for template in "$dev"/registry-templates/*.json; do
  name="$(basename "$template")"
  kind="${name%.json}"
  for target in registry registry-compose; do
    out="$dev/$target/$name"
    # A native kind's installations have no origin, so no edge port either.
    if [[ "$target" == registry ]]; then
      origin="https://\\1.$kind.broker.localhost"
    elif grep -q '@origin:' "$template"; then
      origin="http://\\1.localhost:$(compose_port "$kind")"
    fi
    sed "s|\"@origin:\([a-z0-9-]*\)@\"|\"$origin\"|" "$template" > "$out.tmp"
    for edge in $edges; do
      public="ed25519:$(edge_public_key "$dev/keys/$edge.key")"
      sed -i.bak "s|\"@$edge@\"|\"$public\"|" "$out.tmp" && rm -f "$out.tmp.bak"
    done
    mv "$out.tmp" "$out"
  done
done
echo "Registry files written to $dev/registry (cluster) and $dev/registry-compose (docker compose)"
