# The broker's Keycloak: the official image plus the organization membership extension.
FROM maven:3-eclipse-temurin-21 AS build
WORKDIR /src
COPY extension/pom.xml .
RUN --mount=type=cache,target=/root/.m2 mvn -q -B dependency:go-offline
COPY extension/src src
RUN --mount=type=cache,target=/root/.m2 mvn -q -B package

# Keep in step with keycloak.version in extension/pom.xml.
FROM quay.io/keycloak/keycloak:26.8.0
COPY --from=build /src/target/organization-membership-1.0.0.jar /opt/keycloak/providers/
