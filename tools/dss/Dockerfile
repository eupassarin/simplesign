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
#   http://localhost:8080/simplesign/config.json             what entrypoint.sh set up (trust anchors, lists)
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

# A Spring component that makes the trusted-list job refuse lists whose signature fails (TS 119 615),
# compiled against the web application's own jars and added to its WAR.
FROM eclipse-temurin:21-jdk AS patch
COPY --from=bundle /opt/tomcat/webapps/ROOT.war /war/ROOT.war
COPY SimpleSignTlSynchronization.java /src/
RUN cd /war && mkdir lib && cd lib && jar xf ../ROOT.war WEB-INF/lib \
 && javac -proc:none -cp "/war/lib/WEB-INF/lib/*" -d /war/classes /src/SimpleSignTlSynchronization.java \
 && mkdir -p /war/add/WEB-INF && mv /war/classes /war/add/WEB-INF/classes \
 && cd /war/add && jar uf /war/ROOT.war WEB-INF/classes

FROM eclipse-temurin:21-jre
ARG DSS_VERSION
# Written into /simplesign/config.json (entrypoint.sh), which the TestBench shows.
ENV DSS_VERSION=${DSS_VERSION}
# xmlstarlet reads the certificates out of the Peruvian trusted list (entrypoint.sh).
RUN apt-get update && apt-get install -y --no-install-recommends curl xmlstarlet && rm -rf /var/lib/apt/lists/*
COPY --from=bundle /opt/tomcat /opt/tomcat
COPY --from=patch /war/ROOT.war /opt/tomcat/webapps/ROOT.war
COPY entrypoint.sh /entrypoint.sh
COPY forward.pl /forward.pl
RUN chmod +x /opt/tomcat/bin/*.sh /entrypoint.sh
EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
