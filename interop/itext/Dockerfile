# iText 9 AGPL validator for PAdES interop testing.
#
# Uses iText Core 9 (AGPL) for independent PDF signature validation.
#
# Usage:
#   docker build -t simplesign-itext interop/itext
#   docker run --rm -v $(pwd)/samples:/in simplesign-itext validate-pdf /in/signed.pdf

FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /build
COPY pom.xml .
RUN mvn dependency:resolve -q
COPY src/ src/
RUN mvn package -q -DskipTests

FROM eclipse-temurin:17-jre
WORKDIR /opt/itext
COPY --from=build /build/target/itext-validator-1.0.0.jar /opt/itext/validator.jar

ENTRYPOINT ["java", "-jar", "/opt/itext/validator.jar"]
CMD ["help"]
