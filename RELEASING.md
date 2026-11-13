# Releasing a New Version

Step-by-step guide for releasing a new SimpleSign version.

## Pre-release Checklist

- [ ] All changes committed on `main`
- [ ] `dotnet build SimpleSign.sln --no-restore` passes with 0 warnings
- [ ] Focused projects beneath `tests/unit/` pass on net8.0 and net10.0
- [ ] `SimpleSign.Agent.Tests` passes (the CI runs it on Linux, Windows and macOS)
- [ ] `dotnet test tests/unit/Apps/SimpleSign.Cli.Tests` passes
- [ ] `dotnet test tests/integration/SimpleSign.Integration.Tests` passes when network credentials are available
- [ ] No vulnerable packages: `dotnet list SimpleSign.sln package --vulnerable --no-restore`

## Version Bump — Project Files

Update `<Version>` in all `.csproj` files:

| File | Notes |
|------|-------|
| `Directory.Build.props` | Global default for all projects |
| `src/Formats/SimpleSign/SimpleSign.csproj` | Meta-package |
| `src/Core/SimpleSign.Core/SimpleSign.Core.csproj` | Core crypto |
| `src/Formats/SimpleSign.PAdES/SimpleSign.PAdES.csproj` | Main package |
| `src/TrustFrameworks/Brazil/SimpleSign.Brazil/SimpleSign.Brazil.csproj` | Brazil (shared) |
| `src/TrustFrameworks/Brazil/IcpBrasil/SimpleSign.Brazil.IcpBrasil/SimpleSign.Brazil.IcpBrasil.csproj` | ICP-Brasil |
| `src/TrustFrameworks/Brazil/IcpBrasil/SimpleSign.Brazil.IcpBrasil.Xades/SimpleSign.Brazil.IcpBrasil.Xades.csproj` | ICP-Brasil XAdES |
| `src/TrustFrameworks/Brazil/IcpBrasil/SimpleSign.Brazil.Fiscal/SimpleSign.Brazil.Fiscal.csproj` | Fiscal XML |
| `src/TrustFrameworks/Brazil/GovBr/SimpleSign.Brazil.GovBr/SimpleSign.Brazil.GovBr.csproj` | Gov.br |
| `src/TrustFrameworks/Peru/Iofe/SimpleSign.Peru.Iofe/SimpleSign.Peru.Iofe.csproj` | IOFE (Peru) |
| `src/Signers/SimpleSign.Signers.Pkcs11/SimpleSign.Signers.Pkcs11.csproj` | PKCS#11 tokens and HSMs |
| `src/Signers/SimpleSign.Signers.Cloud/SimpleSign.Signers.Cloud.csproj` | Cloud certificates (PSC, CSC) |
| `src/Formats/SimpleSign.CAdES/SimpleSign.CAdES.csproj` | CAdES signing |
| `src/Formats/SimpleSign.XAdES/SimpleSign.XAdES.csproj` | XAdES signing |
| `src/Extras/SimpleSign.HtmlToPdf/SimpleSign.HtmlToPdf.csproj` | HTML→PDF |
| `src/Apps/SimpleSign.Cli/SimpleSign.Cli.csproj` | CLI tool |

### Quick sed (macOS):

```bash
VERSION="X.Y.Z"
OLD="0.11.0"
sed -i '' "s/<Version>$OLD</<Version>$VERSION</g" \
  Directory.Build.props \
  src/Formats/SimpleSign/SimpleSign.csproj \
  src/Core/SimpleSign.Core/SimpleSign.Core.csproj \
  src/Formats/SimpleSign.PAdES/SimpleSign.PAdES.csproj \
  src/TrustFrameworks/Brazil/SimpleSign.Brazil/SimpleSign.Brazil.csproj \
  src/TrustFrameworks/Brazil/IcpBrasil/SimpleSign.Brazil.IcpBrasil/SimpleSign.Brazil.IcpBrasil.csproj \
  src/TrustFrameworks/Brazil/IcpBrasil/SimpleSign.Brazil.IcpBrasil.Xades/SimpleSign.Brazil.IcpBrasil.Xades.csproj \
  src/TrustFrameworks/Brazil/IcpBrasil/SimpleSign.Brazil.Fiscal/SimpleSign.Brazil.Fiscal.csproj \
  src/TrustFrameworks/Brazil/GovBr/SimpleSign.Brazil.GovBr/SimpleSign.Brazil.GovBr.csproj \
  src/TrustFrameworks/Peru/Iofe/SimpleSign.Peru.Iofe/SimpleSign.Peru.Iofe.csproj \
  src/Signers/SimpleSign.Signers.Pkcs11/SimpleSign.Signers.Pkcs11.csproj \
  src/Signers/SimpleSign.Signers.Cloud/SimpleSign.Signers.Cloud.csproj \
  src/Formats/SimpleSign.CAdES/SimpleSign.CAdES.csproj \
  src/Formats/SimpleSign.XAdES/SimpleSign.XAdES.csproj \
  src/Extras/SimpleSign.HtmlToPdf/SimpleSign.HtmlToPdf.csproj \
  src/Apps/SimpleSign.Cli/SimpleSign.Cli.csproj
```

## Version Bump — Other Files with Hardcoded Versions

These files contain version strings that do NOT come from `<Version>` and must be updated manually:

| File | Location | What to update |
|------|----------|----------------|
| `.github/ISSUE_TEMPLATE/bug_report.md` | `- SimpleSign Version: [e.g. 0.11.0]` | Example version |
| `RELEASING.md` | `OLD="0.11.0"` and `Current version: \`0.11.0\`` | Update both—this file |
| `docs/conformance.md` | the `vX.Y.Z` sentences about EdDSA (the status table and footnote ²) | Both read as "the current version" |
| `docs/articles/agent.md` | the `scripts/package-agent.sh osx-arm64 X.Y.Z` example | Example version |

Run to find any missed occurrences (the `.props`/`.csproj` includes matter—they hold the real
`<Version>`):

```bash
grep -r "$OLD" --include="*.md" --include="*.cs" --include="*.tsx" --include="*.yml" \
  --include="*.props" --include="*.csproj" . \
  | grep -v node_modules | grep -v obj/ | grep -v bin/ | grep -v CHANGELOG.md
```

A hit in a test comment that records where a fixture came from (for example "Captured from version
X.Y.Z") is history, not a version string: leave it alone.

### Signing agent

SimpleSign Agent takes its version from `Directory.Build.props` (`/api/health` reports it). The
release workflow packages it for osx-arm64, osx-x64, linux-x64 and win-x64
(`scripts/package-agent.sh`); the builds are not code-signed.

## Documentation Updates

### CHANGELOG.md

Add a new section at the top (below the header), following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/):

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- ...

### Fixed
- ...

### Changed (Breaking)
- ... (only if applicable)
```

### Breaking changes

If this release breaks public API, describe the change and the replacement under
`### Changed (Breaking)` in CHANGELOG.md, with a short before/after when it helps.

### Architecture Decision Records (ADRs)

If this release introduced **significant architectural decisions**:
- [ ] Create new ADR in `docs/adr/` (follow numbering: `NNNN-slug.md`)
- [ ] Follow existing ADR format: Status, Context, Decision, Consequences, Alternatives

## Build & Test

```bash
dotnet build SimpleSign.sln --no-restore
dotnet test tests/unit/Formats/SimpleSign.Contracts.Tests --no-restore
dotnet test tests/unit/Formats/SimpleSign.PAdES.Tests --no-restore
dotnet test tests/unit/Formats/SimpleSign.CAdES.Tests --no-restore
dotnet test tests/unit/Formats/SimpleSign.XAdES.Tests --no-restore
dotnet test tests/unit/Apps/SimpleSign.Cli.Tests --no-restore
dotnet test tests/unit/Core/SimpleSign.Core.Tests --no-restore
dotnet test tests/unit/TrustFrameworks/Peru/Iofe/SimpleSign.Peru.Iofe.Tests --no-restore
```

Run the AOT smoke publish on a Linux x64 runner (the release workflow is the
authoritative environment), because NativeAOT's Linux linker and symbol-stripper
are required. Do not add `--no-restore` for the first publish of a runtime ID:
that RID needs its own restore assets.

```bash
dotnet publish tests/smoke/SimpleSign.AotSmokeTest -r linux-x64 -f net10.0
```

## Commit & Tag

```bash
git add .
git commit -m "chore: bump version to X.Y.Z"
git tag vX.Y.Z
git push origin main --tags
```

The tag push triggers `.github/workflows/release.yml` which builds, tests, packs NuGet packages, publishes to NuGet.org, and creates the GitHub Release with the SimpleSign Agent binaries. The CLI ships only as the `SimpleSign.Cli` .NET tool on NuGet.

## Manual NuGet Push (if CI fails)

```bash
dotnet pack -c Release -o ./artifacts
# Push every package of this version (Core, formats, country packages, signers, HtmlToPdf, the CLI tool, the meta-package)
for package in ./artifacts/*.X.Y.Z.nupkg; do
  dotnet nuget push "$package" --api-key $NUGET_KEY --source https://api.nuget.org/v3/index.json
done
```

## GitHub Release

```bash
gh release create vX.Y.Z --title "vX.Y.Z" --notes-file - << 'NOTES'
## What's New

(paste highlights from CHANGELOG.md)
NOTES
```

## Versioning Policy

While SimpleSign is on **0.x**, the public API is not yet declared stable, and SemVer allows a
breaking change in a minor bump:

- **PATCH** (0.x.Y): Bug fixes, performance, internal improvements, new non-breaking features
- **MINOR** (0.X.0): New public API surface, deprecations, **and breaking changes**—described under
  `### Changed (Breaking)` in CHANGELOG.md, with a before/after and a migration guide when the
  change is wide (as 0.11.0 did for the `SimpleSign.Brasil` → `SimpleSign.Brazil.*` split)
- **MAJOR** (x.0.0): reserved for 1.0, which is when the public API becomes stable; after that,
  breaking changes move to MAJOR

Current version: `0.11.0`
