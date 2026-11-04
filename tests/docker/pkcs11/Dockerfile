# Test image for the PKCS#11 signer: .NET 10 SDK + .NET 8 runtime, SoftHSM2 (software token),
# OpenSC (pkcs11-tool), OpenSSL and clang (for the Native AOT smoke test).
# Used by scripts/tests/pkcs11.sh; CI installs the same packages on ubuntu-latest instead.
FROM mcr.microsoft.com/dotnet/runtime:8.0 AS runtime8

FROM mcr.microsoft.com/dotnet/sdk:10.0
COPY --from=runtime8 /usr/share/dotnet/shared/Microsoft.NETCore.App /usr/share/dotnet/shared/Microsoft.NETCore.App

RUN apt-get update \
    && apt-get install -y --no-install-recommends softhsm2 opensc openssl clang zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1
WORKDIR /work
