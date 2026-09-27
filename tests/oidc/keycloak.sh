#!/bin/bash
# keycloak.sh: a Keycloak with realm rgwi ( tests/oidc/realm.json ) on
# localhost:8080, for the single sign-on test: alice is in rgw-admins, bob is not
set -eu
podman rm -f rgwi-keycloak >/dev/null 2>&1 || true
podman run -d --name rgwi-keycloak -p 127.0.0.1:8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -v "$(cd "$(dirname "$0")" && pwd)/realm.json:/opt/keycloak/data/import/realm.json:Z" \
  quay.io/keycloak/keycloak:26.3 start-dev --import-realm --hostname=http://localhost:8080 >/dev/null
for i in $(seq 90); do
  curl -sf -o /dev/null http://localhost:8080/realms/rgwi/.well-known/openid-configuration && { echo "keycloak is up"; exit 0; }
  sleep 2
done
echo "keycloak did not come up"; podman logs --tail 20 rgwi-keycloak; exit 1
