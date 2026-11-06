# The EU DSS demo web application (https://github.com/esig/dss-demonstrations) as a local
# validation service, for the TestBench's cross-validation.
#
# The European Commission publishes the web application only inside its Windows bundle
# (Tomcat + ROOT.war + a Windows JRE). This image takes the Tomcat with the web application
# from that bundle and runs it on a Linux JRE.
#
#   docker compose -f tools/dss/docker-compose.yml up --build
#   http://localhost:8080/                                   the DSS demo pages
#   http://localhost:8080/services/rest/validation           the REST validation service
ARG DSS_VERSION=6.3

FROM alpine:3.21 AS bundle
ARG DSS_VERSION
RUN apk add --no-cache curl unzip
# The Commission's server is slow (about 0.5 MB/s, so around 13 minutes). The zip is kept in a
# build cache and the download resumes (-C -), so an interrupted build does not start over.
RUN --mount=type=cache,target=/var/cache/dss \
    curl -fSL --retry 8 --retry-all-errors -C - -o "/var/cache/dss/dss-demo-bundle-${DSS_VERSION}.zip" \
      "https://ec.europa.eu/digital-building-blocks/artifact/repository/esignaturedss/eu/europa/ec/joinup/sd-dss/dss-demo-bundle/${DSS_VERSION}/dss-demo-bundle-${DSS_VERSION}.zip" \
 && unzip -q "/var/cache/dss/dss-demo-bundle-${DSS_VERSION}.zip" "dss-demo-bundle-${DSS_VERSION}/apache-tomcat-*" -d /tmp/dss \
 && mv /tmp/dss/dss-demo-bundle-${DSS_VERSION}/apache-tomcat-* /opt/tomcat \
 && rm -rf /tmp/dss

FROM eclipse-temurin:21-jre
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY --from=bundle /opt/tomcat /opt/tomcat
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /opt/tomcat/bin/*.sh /entrypoint.sh
EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
