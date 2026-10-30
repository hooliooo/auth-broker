#!/usr/bin/env bash
# Creates or updates the local Kubernetes cluster (kind) with the auth broker: Keycloak, the hub,
# one edge per app kind and their stand-in APIs, behind an ingress with certificates from the
# local development CA. Every public name is under broker.localhost:
#
#   https://keycloak.broker.localhost       Keycloak (realm broker)
#   https://hub.broker.localhost            the hub
#   https://<site>.<kind>.broker.localhost  a site, served by its kind's edge
#
# Once per machine: brew install kind helm mkcert nss && mkcert -install
#
#   dev/k8s/up.sh       # idempotent: rerun after changing code, manifests or the registry templates
#   dev/k8s/down.sh     # deletes the cluster
#
# Every kubectl and helm call names the cluster's own context, so no other cluster (such as a
# shared one your kubeconfig points at) is ever touched. The docker compose stack at the root is
# only the measurement stack for perf/ now.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cluster=auth-broker
ctx="kind-$cluster"
ns=auth-broker
k() { kubectl --context "$ctx" "$@"; }
h() { helm --kube-context "$ctx" "$@"; }
step() { printf '\n==> %s\n' "$*"; }

# ---- Preflight: everything a first run needs, each with what to do about it ----
problems=()
for tool in docker kind kubectl helm mkcert openssl jq; do
  command -v "$tool" >/dev/null || problems+=("$tool is not installed: see README.md, 'Local cluster'")
done
if ! command -v docker >/dev/null; then
  :
elif ! docker info >/dev/null 2>&1; then
  problems+=("Docker is not running: start Docker Desktop (or the Docker daemon)")
else
  memory=$(docker info --format '{{.MemTotal}}')
  if (( memory < 4 * 1024 * 1024 * 1024 )); then
    problems+=("Docker has $((memory / 1024 / 1024)) MiB of memory; the stack needs at least 4 GiB (Docker Desktop: Settings > Resources)")
  fi
fi
ca_root="$(command -v mkcert >/dev/null && mkcert -CAROOT || true)"
if [[ -z "$ca_root" || ! -f "$ca_root/rootCA.pem" || ! -f "$ca_root/rootCA-key.pem" ]]; then
  problems+=("no local CA yet: run 'mkcert -install' (it asks for your password)")
elif [[ "$(uname)" == Darwin ]] && ! security verify-cert -c "$ca_root/rootCA.pem" -p ssl >/dev/null 2>&1; then
  problems+=("the local CA is not trusted by macOS: run 'mkcert -install'")
fi
# The cluster's ports on this machine must be free unless this cluster already holds them. The
# docker compose stack and auth-api's cluster use some of the same ports: one at a time.
if command -v kind >/dev/null && ! kind get clusters 2>/dev/null | grep -qx "$cluster"; then
  for port in 80 443 6380 8091 5290 8181 8182 8183 8184 8185; do
    if command -v lsof >/dev/null && lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
      problems+=("port $port is already in use on this machine (lsof -nP -iTCP:$port -sTCP:LISTEN shows by what); stop it first")
    fi
  done
fi
if (( ${#problems[@]} > 0 )); then
  echo "Cannot set up the cluster yet:"
  for problem in "${problems[@]}"; do echo "  - $problem"; done
  exit 1
fi

step "Keys and registry"
# This machine's own keys, made once and never committed, and the registry built from them.
"$root/dev/generate-dev-keys.sh"

step "Cluster $cluster"
if ! kind get clusters | grep -qx "$cluster"; then
  # The nodes see this checkout's dev/registry at /registry; kind needs its absolute path.
  config="$(mktemp)"
  trap 'rm -f "$config"' EXIT
  sed "s|@REGISTRY_DIR@|$root/dev/registry|" "$root/deploy/kind/cluster.yaml" > "$config"
  # kind makes its new cluster the default context; keep whatever was the default before.
  previous="$(kubectl config current-context 2>/dev/null || true)"
  kind create cluster --config "$config"
  if [[ -n "$previous" ]]; then kubectl config use-context "$previous" >/dev/null; fi
fi

step "Ingress controller (Traefik)"
helm repo add traefik https://traefik.github.io/charts >/dev/null 2>&1 || true
helm repo add jetstack https://charts.jetstack.io >/dev/null 2>&1 || true
helm repo update traefik jetstack >/dev/null
h upgrade --install traefik traefik/traefik --namespace traefik --create-namespace \
  --version 42.1.3 --values "$root/deploy/platform/traefik-values.yaml" --wait

step "Certificates (cert-manager, local CA)"
h upgrade --install cert-manager jetstack/cert-manager --namespace cert-manager \
  --create-namespace --version v1.21.2 --set crds.enabled=true --wait
k -n cert-manager create secret tls local-ca \
  --cert="$ca_root/rootCA.pem" --key="$ca_root/rootCA-key.pem" \
  --dry-run=client -o yaml | k apply -f -
k apply -f "$root/deploy/platform/cluster-issuer.yaml"

step "In-cluster DNS: the public names pods call resolve to the ingress"
# Pods then reach Keycloak and the hub exactly as browsers do, like split-horizon DNS in
# production. Each name gets a rewrite block ahead of the kubernetes plugin.
corefile="$(k -n kube-system get configmap coredns -o jsonpath='{.data.Corefile}')"
if ! grep -q 'broker public names' <<<"$corefile"; then
  rewrites="    # broker public names, answered with the ingress controller's address\n"
  for name in keycloak.broker.localhost hub.broker.localhost; do
    rewrites+="    rewrite stop {\n        name exact $name traefik.traefik.svc.cluster.local\n        answer name traefik.traefik.svc.cluster.local $name\n    }\n"
  done
  corefile="$(awk -v r="$rewrites" '/^ *kubernetes cluster.local/ && !done { printf "%s", r; done=1 } { print }' <<<"$corefile")"
  k -n kube-system create configmap coredns --from-literal=Corefile="$corefile" \
    --dry-run=client -o yaml | k apply -f -
  k -n kube-system rollout restart deployment coredns
  k -n kube-system rollout status deployment coredns --timeout=120s
fi

step "Images"
docker build -t auth-broker-kind-edge:dev "$root"
docker build -t auth-broker-kind-edge-test-helpers:dev -f "$root/crates/test-helpers/Dockerfile" "$root"
docker build -t auth-broker-kind-edge-keycloak:dev "$root/providers/keycloak"
docker build -t auth-broker-kind-edge-keycloak-config:dev "$root/providers/keycloak/config"
kind load docker-image --name "$cluster" auth-broker-kind-edge:dev \
  auth-broker-kind-edge-test-helpers:dev auth-broker-kind-edge-keycloak:dev \
  auth-broker-kind-edge-keycloak-config:dev

step "Namespace, secrets and setup scripts"
k apply -f "$root/deploy/k8s/namespace.yaml"
# Random secrets, created once and kept across reruns; read them back with kubectl.
secret_once() { # <name> <key=value>...
  local name=$1; shift
  k -n "$ns" get secret "$name" >/dev/null 2>&1 && return
  local args=()
  for pair in "$@"; do args+=(--from-literal="$pair"); done
  k -n "$ns" create secret generic "$name" "${args[@]}"
}
random() { openssl rand -base64 24 | tr -d '/+=' | head -c 24; }
secret_once keycloak-admin username=admin "password=$(random)"
secret_once keycloak-db "password=$(random)"
secret_once registry-db "password=$(random)"
# This machine's keys (dev/keys), replaced whenever they change.
k -n "$ns" create secret generic hub-client-key \
  --from-file=hub-client-key.pem="$root/dev/keys/hub-client-key.pem" \
  --dry-run=client -o yaml | k apply -f -
edge_keys=()
for key in "$root"/dev/keys/edge-*.key; do edge_keys+=(--from-file="$key"); done
k -n "$ns" create secret generic edge-keys "${edge_keys[@]}" --dry-run=client -o yaml | k apply -f -
k -n "$ns" create secret generic registry-provisioner \
  --from-file=secret="$root/dev/keys/registry-provisioner.secret" \
  --dry-run=client -o yaml | k apply -f -
# The local CA's certificate (public only), for pods that call the public names.
k -n "$ns" create configmap local-ca --from-file=ca.crt="$ca_root/rootCA.pem" \
  --dry-run=client -o yaml | k apply -f -
k -n "$ns" create configmap keycloak-setup-scripts \
  --from-file="$root/providers/keycloak/setup" --dry-run=client -o yaml | k apply -f -

step "Keycloak"
k apply -k "$root/deploy/k8s"
k -n "$ns" rollout status statefulset keycloak-postgres --timeout=180s
k -n "$ns" rollout status deployment keycloak --timeout=600s
k -n "$ns" wait certificate keycloak-tls --for=condition=Ready --timeout=120s

step "Realm setup"
# Idempotent, so it runs on every pass and picks up changed clients, users and organizations.
k -n "$ns" delete job keycloak-setup --ignore-not-found
k apply -f "$root/deploy/k8s/keycloak-setup-job.yaml"
if ! k -n "$ns" wait job keycloak-setup --for=condition=Complete --timeout=600s; then
  k -n "$ns" logs job/keycloak-setup --all-containers | tail -40
  echo "Realm setup failed; see above."
  exit 1
fi

step "Registry store"
# Seeds the store from this checkout's registry files; installations added through the admin API
# since are kept.
k -n "$ns" rollout status statefulset registry-postgres --timeout=180s
k -n "$ns" delete job registry-seed --ignore-not-found
k apply -f "$root/deploy/k8s/registry-seed-job.yaml"
if ! k -n "$ns" wait job registry-seed --for=condition=Complete --timeout=300s; then
  k -n "$ns" logs job/registry-seed --all-containers | tail -40
  echo "Registry seeding failed; see above."
  exit 1
fi
k -n "$ns" logs job/registry-seed

step "Broker"
# Restarts the deployments named, and returns once only their new pods are left: a rollout
# counts as done when the new pods are ready, while the old ones may still be stopping and
# reachable. The test helpers keep their state in memory, so nothing may reach an old one.
restart() { # <deployment>...
  local name pods old=()
  for name in "$@"; do
    read -r -a pods <<<"$(k -n "$ns" get pods -l "app=$name" -o jsonpath='{.items[*].metadata.name}')"
    old+=(${pods[@]+"${pods[@]}"}) # macOS's bash 3.2 refuses an empty "${pods[@]}" under set -u
  done
  for name in "$@"; do k -n "$ns" rollout restart deployment "$name"; done
  for name in "$@"; do k -n "$ns" rollout status deployment "$name" --timeout=240s; done
  if (( ${#old[@]} > 0 )); then
    k -n "$ns" wait --for=delete pod "${old[@]}" --timeout=120s >/dev/null
  fi
}
# In dependency order: the hub reaches Keycloak through the helpers' proxy, and the edges are
# ready only once the hub answers. Restarted for rebuilt images, new keys and the new realm.
k -n "$ns" rollout status deployment redis --timeout=120s
restart test-helpers
restart api-inspection api-billing api-plant-d api-plant-e api-planner
restart hub
restart edge-inspection edge-billing edge-maintenance
for certificate in hub-tls registry-admin-tls edge-inspection-tls edge-billing-tls edge-maintenance-tls; do
  k -n "$ns" wait certificate "$certificate" --for=condition=Ready --timeout=120s
done

cat <<DONE

Keycloak:        https://keycloak.broker.localhost        (admin console: /admin, realm broker)
Hub:             https://hub.broker.localhost
Registry admin:  https://registry.broker.localhost  (client registry-provisioner, secret in dev/keys)
Sites:           https://plant-a.inspection.broker.localhost, plant-b.inspection
                 https://plant-c.billing.broker.localhost
                 https://plant-d.maintenance.broker.localhost, plant-e.maintenance
Native:          the planner kind's desktop installations plant-f and plant-g, calling their
                 API at http://localhost:8185, and the inspection kind's plant-i, at
                 http://localhost:8181 (crates/native-app)
                 (Chrome and Firefox resolve *.localhost by themselves; Safari does not)
Admin password:  kubectl --context $ctx -n $ns get secret keycloak-admin -o jsonpath='{.data.password}' | base64 -d
E2E tests:       cargo test -p e2e --features e2e
DONE
