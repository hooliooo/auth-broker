#!/bin/bash
# The organization sync job: one Keycloak organization per site of every kind whose
# edges call their API directly (registry entries without api_upstream). Creates and updates
# them from the registry files in $registry_dir, and reports drift: organizations it manages
# that are no longer in the registry. Idempotent; run it whenever the registry changes.
#
# An organization's alias is the site id and never changes; its `tenant` attribute is the
# site's tenant; a site with "enabled": false disables its organization, so Keycloak refuses
# its tokens at the next refresh.
set -euo pipefail
registry_dir="${registry_dir:-/mnt/registry}"
export KC_OPTS='-Duser.home=/tmp'

$kcadm config credentials --server "$keycloak_url" --realm master \
  --user "$KEYCLOAK_ADMIN" --password "$KEYCLOAK_ADMIN_PASSWORD" >/dev/null

declare -A wanted=()
for doc in "$registry_dir"/*.json; do
  [[ "$(jq -r '.app.api_upstream == null' "$doc")" == "true" ]] || continue
  while read -r site; do
    id=$(jq -r '.id' <<<"$site")
    tenant=$(jq -r '.tenant' <<<"$site")
    enabled=$(jq -r '.enabled // true' <<<"$site")
    wanted[$id]=1
    attributes="{\"tenant\": [\"$tenant\"], \"managed-by\": [\"hub\"]}"
    existing=$($kcadm get organizations -r "$realm" -q "search=$id" -q exact=true | jq -r ".[] | select(.alias == \"$id\") | .id")
    if [[ -z "$existing" ]]; then
      $kcadm create organizations -r "$realm" -s "name=$id" -s "alias=$id" -s "enabled=$enabled" \
        -s "attributes=$attributes" >/dev/null
      echo "organization $id created"
    else
      $kcadm update "organizations/$existing" -r "$realm" -s "enabled=$enabled" -s "attributes=$attributes"
      echo "organization $id up to date"
    fi
  done < <(jq -c '.sites[]' "$doc")
done

while read -r alias; do
  [[ -n "$alias" && -z "${wanted[$alias]:-}" ]] && echo "DRIFT: organization $alias is managed by the hub but not in the registry"
done < <(for id in $($kcadm get organizations -r "$realm" | jq -r '.[].id'); do
  # The list leaves attributes out; each organization is read in full.
  $kcadm get "organizations/$id" -r "$realm" | jq -r 'select(.attributes["managed-by"] == ["hub"]) | .alias'
done)
exit 0
