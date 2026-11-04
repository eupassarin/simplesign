#!/usr/bin/env bash
# SimpleSign - PKCS#11 tests in Docker (SoftHSM2), for machines without SoftHSM
# Usage: ./pkcs11.sh
# Builds tests/docker/pkcs11, copies the repository into the container (without bin/obj) and
# runs scripts/tests/pkcs11-run.sh there. The NuGet cache is kept in a Docker volume.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMAGE="simplesign-pkcs11-test"

docker build -t "$IMAGE" "$REPO_ROOT/tests/docker/pkcs11"
# The copy has no .git, so SourceLink is turned off (MSBuild reads environment variables as properties).
docker run --rm \
  -e EnableSourceLink=false -e EnableSourceControlManagerQueries=false \
  -v "$REPO_ROOT":/src:ro \
  -v simplesign-pkcs11-nuget:/root/.nuget/packages \
  "$IMAGE" bash -c '
    set -euo pipefail
    tar -C /src --exclude=./.git --exclude=./node_modules --exclude=./BenchmarkDotNet.Artifacts \
      --exclude="*/bin" --exclude="*/obj" --exclude="*/TestResults" -cf - . | tar -C /work -xf -
    cd /work
    scripts/tests/pkcs11-run.sh
  '
