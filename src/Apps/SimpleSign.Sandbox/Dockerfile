# The SimpleSign Sandbox (test PKI, CRL over HTTP/HTTPS/LDAP, OCSP, TSA, CSC) in a container. API only:
# its UI is the TestBench's Sandbox control (connect it to http://localhost:5300).
# Built from the repository root, since the Sandbox references the library's projects:
#   docker build -f src/Apps/SimpleSign.Sandbox/Dockerfile -t simplesign-sandbox .
#   docker run --rm -p 127.0.0.1:5300-5302:5300-5302 -v sandbox-data:/data simplesign-sandbox
# tools/stack/docker-compose.yml runs it with DSS; see tools/stack/README.md.

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
WORKDIR /repo
COPY global.json Directory.Build.props .editorconfig ./
COPY src/ src/
# No .git in the context: no SourceLink.
RUN dotnet publish src/Apps/SimpleSign.Sandbox -c Release -o /app \
      -p:EnableSourceLink=false -p:PublishRepositoryUrl=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY --from=build /app /app
WORKDIR /app
# The environment (PKI, keys, state) lives in /data: mount a volume to keep it between runs.
VOLUME /data
EXPOSE 5300 5301 5302
HEALTHCHECK --interval=5s --timeout=3s --start-period=30s --retries=12 \
  CMD curl -fsS http://localhost:5300/api/info > /dev/null || exit 1
# --listen-any: HTTP, HTTPS and LDAP must answer outside the container's loopback.
# --allow-remote-admin: requests published from the host arrive from the Docker bridge, not from loopback;
# publish the ports on 127.0.0.1 only so the admin API (private keys, revocations) stays on this machine.
# The certificates keep pointing to http://localhost:5300 (override with --public-base-url).
ENTRYPOINT ["dotnet", "SimpleSign.Sandbox.dll", "--listen-any", "--allow-remote-admin", "--data-dir", "/data"]
