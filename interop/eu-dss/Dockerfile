# EU DSS (Digital Signature Service) validator for ETSI EN 319 102 conformance testing.
#
# Builds a minimal Java CLI that uses the official EU DSS library to validate
# PAdES, CAdES, and XAdES signatures per ETSI standards.
#
# Usage:
#   docker build -t simplesign-eu-dss interop/eu-dss
#   docker run --rm -v $(pwd)/samples:/in simplesign-eu-dss validate-pades /in/signed.pdf

FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /build
COPY pom.xml .
# Download dependencies first (layer caching)
RUN mvn dependency:resolve -q
COPY src/ src/
RUN mvn package -q -DskipTests

FROM eclipse-temurin:17-jre
WORKDIR /opt/dss
COPY --from=build /build/target/dss-validator-1.0.0.jar /opt/dss/validator.jar

ENTRYPOINT ["java", "-jar", "/opt/dss/validator.jar"]
CMD ["help"]
