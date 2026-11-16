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
#
# The base images are pinned by digest (the multi-platform index, amd64 and arm64) and the bundle by
# its SHA-256: a change upstream fails the build instead of changing what is validated. To move to
# another DSS version, pass both DSS_VERSION and DSS_SHA256 (sha256sum of the new zip); to refresh
# a base image, `docker buildx imagetools inspect <image>` gives the new digest.
ARG DSS_VERSION=6.3
ARG DSS_SHA256=60452c53eb395106655340890a207885f165bf844485046e3a1f8535ef8fa944

FROM alpine:3.21@sha256:bc21487101ae47172509130ee1092cc273a831968d64b617776d1f69c81e42ab AS bundle
ARG DSS_VERSION
ARG DSS_SHA256
RUN apk add --no-cache curl unzip
# The Commission's server is slow (0.1 to 0.5 MB/s, so 15 to 60 minutes) and often closes the
# connection mid-transfer. The zip is kept in a build cache and each attempt resumes where the last
# one stopped (one curl -C - per attempt: curl's own --retry would start over from the first byte),
# so neither a dropped connection nor an interrupted build starts over.
# A complete zip whose hash differs is deleted from the cache, so the next build downloads it again.
RUN --mount=type=cache,target=/var/cache/dss \
    zip="/var/cache/dss/dss-demo-bundle-${DSS_VERSION}.zip" \
 && url="https://ec.europa.eu/digital-building-blocks/artifact/repository/esignaturedss/eu/europa/ec/joinup/sd-dss/dss-demo-bundle/${DSS_VERSION}/dss-demo-bundle-${DSS_VERSION}.zip" \
 && attempt=0 \
 && until curl -fsSL -C - -o "$zip" "$url"; do \
      attempt=$((attempt + 1)); \
      if [ "$attempt" -ge 100 ]; then echo "could not download $url" >&2; exit 1; fi; \
      echo "download interrupted at $(wc -c < "$zip" 2>/dev/null || echo 0) bytes; resuming (attempt $attempt)"; \
      sleep 5; \
    done \
 && if ! echo "${DSS_SHA256}  $zip" | sha256sum -c -; then \
      echo "dss-demo-bundle-${DSS_VERSION}.zip: SHA-256 $(sha256sum "$zip" | cut -d' ' -f1), expected ${DSS_SHA256}" >&2; \
      rm -f "$zip"; exit 1; \
    fi \
 && unzip -q "$zip" "dss-demo-bundle-${DSS_VERSION}/apache-tomcat-*" -d /tmp/dss \
 && mv /tmp/dss/dss-demo-bundle-${DSS_VERSION}/apache-tomcat-* /opt/tomcat \
 && rm -rf /tmp/dss

# A Spring component that makes the trusted-list job refuse lists whose signature fails (TS 119 615),
# compiled against the web application's own jars and added to its WAR.
FROM eclipse-temurin:21-jdk@sha256:0a3f329821dcadf54b2a3033a15e2e9f007069a9db43d7f51897e6b80e726b07 AS patch
COPY --from=bundle /opt/tomcat/webapps/ROOT.war /war/ROOT.war
COPY SimpleSignTlSynchronization.java /src/
RUN cd /war && mkdir lib && cd lib && jar xf ../ROOT.war WEB-INF/lib \
 && javac -proc:none -cp "/war/lib/WEB-INF/lib/*" -d /war/classes /src/SimpleSignTlSynchronization.java \
 && mkdir -p /war/add/WEB-INF && mv /war/classes /war/add/WEB-INF/classes \
 && cd /war/add && jar uf /war/ROOT.war WEB-INF/classes

FROM eclipse-temurin:21-jre@sha256:18bb4a91a3dea3f03ee31d3755af34dfb40f904fc77ab56cdc2f092e32fff9c2
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
