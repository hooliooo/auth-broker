# keep version in sync with keycloak/Dockerfile
FROM quay.io/keycloak/keycloak:26.7.0 AS keycloak

FROM eclipse-temurin:25.0.3_9-jre-jammy
RUN find /etc/apt -type f \( -name '*.list' -o -name '*.sources' \) \
        -exec sed -i 's|http://|https://|g' {} + && \
    apt-get update && \
    apt-get install -y --no-install-recommends curl jq bash && \
    rm -rf /var/lib/apt/lists/*

ENV kcadm=/opt/keycloak/bin/kcadm.sh
COPY --from=keycloak $kcadm $kcadm
COPY --from=keycloak /opt/keycloak/bin/client /opt/keycloak/bin/client
