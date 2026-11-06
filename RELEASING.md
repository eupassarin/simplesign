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
| `src/Formats/SimpleSign.CAdES/SimpleSign.CAdES.csproj` | CAdES signing |
| `src/Formats/SimpleSign.XAdES/SimpleSign.XAdES.csproj` | XAdES signing |
| `src/Extras/SimpleSign.HtmlToPdf/SimpleSign.HtmlToPdf.csproj` | HTML→PDF |
| `src/Apps/SimpleSign.Cli/SimpleSign.Cli.csproj` | CLI tool |

### Quick sed (macOS):

```bash
VERSION="X.Y.Z"
OLD="0.10.1"
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
  src/Formats/SimpleSign.CAdES/SimpleSign.CAdES.csproj \
  src/Formats/SimpleSign.XAdES/SimpleSign.XAdES.csproj \
  src/Extras/SimpleSign.HtmlToPdf/SimpleSign.HtmlToPdf.csproj \
  src/Apps/SimpleSign.Cli/SimpleSign.Cli.csproj
```

## Version Bump — Other Files with Hardcoded Versions

These files contain version strings that do NOT come from `<Version>` and must be updated manually:

| File | Location | What to update |
|------|----------|----------------|
| `.github/ISSUE_TEMPLATE/bug_report.md` | `- SimpleSign Version: [e.g. 0.10.1]` | Example version |
| `RELEASING.md` | `OLD="0.10.1"` and `Current version: \`0.10.1\`` | Update both—this file |

Run to find any missed occurrences:

```bash
grep -r "$OLD" --include="*.md" --include="*.cs" --include="*.tsx" --include="*.yml" . \
  | grep -v node_modules | grep -v obj/ | grep -v bin/ | grep -v CHANGELOG.md
```

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
dotnet nuget push ./artifacts/SimpleSign.Core.X.Y.Z.nupkg --api-key $NUGET_KEY --source https://api.nuget.org/v3/index.json
dotnet nuget push ./artifacts/SimpleSign.PAdES.X.Y.Z.nupkg --api-key $NUGET_KEY --source https://api.nuget.org/v3/index.json
dotnet nuget push ./artifacts/SimpleSign.Brazil.IcpBrasil.X.Y.Z.nupkg --api-key $NUGET_KEY --source https://api.nuget.org/v3/index.json
dotnet nuget push ./artifacts/SimpleSign.CAdES.X.Y.Z.nupkg --api-key $NUGET_KEY --source https://api.nuget.org/v3/index.json
dotnet nuget push ./artifacts/SimpleSign.XAdES.X.Y.Z.nupkg --api-key $NUGET_KEY --source https://api.nuget.org/v3/index.json
dotnet nuget push ./artifacts/SimpleSign.HtmlToPdf.X.Y.Z.nupkg --api-key $NUGET_KEY --source https://api.nuget.org/v3/index.json
dotnet nuget push ./artifacts/SimpleSign.X.Y.Z.nupkg --api-key $NUGET_KEY --source https://api.nuget.org/v3/index.json
```

## GitHub Release

```bash
gh release create vX.Y.Z --title "vX.Y.Z" --notes-file - << 'NOTES'
## What's New

(paste highlights from CHANGELOG.md)
NOTES
```

## Versioning Policy

- **PATCH** (0.5.x): Bug fixes, performance, internal improvements, new non-breaking features
- **MINOR** (0.x.0): New public API surface, deprecations
- **MAJOR** (x.0.0): Breaking changes to public API

Current version: `0.10.1`
