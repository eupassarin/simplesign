# The SimpleSign Sandbox (test PKI, CRL over HTTP/HTTPS/LDAP, OCSP, TSA, CSC) in a container.
# Built from the repository root, since the Sandbox references the library's projects:
#   docker build -f src/Apps/SimpleSign.Sandbox/Dockerfile -t simplesign-sandbox .
#   docker run --rm -p 127.0.0.1:5300-5302:5300-5302 -v sandbox-data:/data simplesign-sandbox
# tools/stack/docker-compose.yml runs it with DSS; see tools/stack/README.md.

# The web UI (React), built once here so the .NET stage does not need Node.js.
FROM node:22-bookworm-slim AS web
WORKDIR /web
COPY src/Apps/SimpleSign.Sandbox/web/package.json src/Apps/SimpleSign.Sandbox/web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY src/Apps/SimpleSign.Sandbox/web/ ./
RUN npm run build

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
WORKDIR /repo
COPY global.json Directory.Build.props .editorconfig ./
COPY src/ src/
COPY --from=web /web/dist src/Apps/SimpleSign.Sandbox/web/dist
# No .git in the context: no SourceLink.
RUN dotnet publish src/Apps/SimpleSign.Sandbox -c Release -o /app \
      -p:SkipWeb=true -p:EnableSourceLink=false -p:PublishRepositoryUrl=false \
 && rm -rf /app/web

FROM mcr.microsoft.com/dotnet/aspnet:10.0
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY --from=build /app /app
# The Sandbox serves its UI from wwwroot next to the binary (SandboxApp.MapUi).
COPY --from=web /web/dist /app/wwwroot
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
ENTRYPOINT ["dotnet", "SimpleSign.Sandbox.dll", "--listen-any", "--allow-remote-admin", "--no-browser", "--data-dir", "/data"]
