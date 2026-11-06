# ADR 0018: Repository Layout and Package Boundaries

**Status:** Accepted

**Context:**
By v0.11 the repository held 20 projects under `src/`, around 16 test projects, three web samples, a BenchmarkDotNet suite, Java/Docker interop harnesses, a fuzz harness, Stryker mutation testing, a docfx site, nine migration guides and three overlapping instruction files for coding agents. One person maintains it.

Two pressures pulled in opposite directions:
- **Split it up.** The Brazilian packages and the apps (CLI, Agent, TestBench) have a different audience and release rhythm from the core libraries, and `SimpleSign.Brasil` used Core, PAdES and CAdES internals through `InternalsVisibleTo`. As a result Core carried ICP-Brasil OIDs and log events.
- **Keep it together.** Core and Brasil still change together, often in the same week. With separate repositories, every Core change that Brasil needs becomes a cycle: publish to NuGet, bump the version in the other repository, then test.

**Decision:**
Stay a **single repository**, but make the boundaries real so that a later split is cheap.

1. **Country packages use the public API only.** No project outside the Brazil family grants `InternalsVisibleTo` to `SimpleSign.Brazil*`. Inside the family, the shared `SimpleSign.Brazil` grants it to `SimpleSign.Brazil.IcpBrasil` and `SimpleSign.Brazil.GovBr` (SubjectAltName parsing, CPF/CNPJ check digits, the revocation checker), which never reference each other. Generic building blocks a country package needs are made public in Core with XML docs: `CrlEvaluator`, `CrlClient.GetCrlUri`, `OcspClient.GetOcspUri`, `ResilientHttp.GetBytesAsync`, and the builders' `SignerCertificate`/`SignerChain`. Country-specific constants, OID arcs and log events live in the country package. See ADR 0009.
2. **Internal infrastructure sits in `Internal/` folders** of each project (logs, DER helpers, revocation plumbing), so the public surface of a package can be read from its folder tree.
3. **Apps live in the repository** (`SimpleSign.Cli`, `SimpleSign.Agent`, `SimpleSign.TestBench`). They reference the libraries by project and are not part of the NuGet dependency graph of the libraries.
4. **Projects are grouped by role** under `src/`: `Core/` (Core), `Formats/` (PAdES, CAdES, XAdES and the `SimpleSign` meta-package), `TrustFrameworks/` (ICP-Brasil today; room for eIDAS, IOFE and other national or regional trust frameworks), `Signers/`, `Extras/` (HtmlToPdf) and `Apps/`. The `.sln` has a solution folder for each group. Project, assembly and namespace names do not depend on the group.
5. **The PDF parser is part of `SimpleSign.PAdES`.** `SimpleSign.Pdf` had no consumer besides PAdES and exposed its internals to it through `InternalsVisibleTo`, so it was a PAdES component split across two packages. It now lives in `src/Formats/SimpleSign.PAdES/Pdf/` (namespace `SimpleSign.PAdES.Pdf`) and the `SimpleSign.Pdf` package is discontinued.
6. **Only what is product or core verification stays.** Samples, benchmarks, the interop harnesses, fuzzing, mutation testing, the docfx site, the migration guides and `llms*.txt` were removed. Documentation is plain Markdown in `docs/articles` and `docs/adr`. Breaking changes are described in `CHANGELOG.md`. The removed material remains available at tag `pre-cleanup`.

**Consequences:**
- A Core change and the Brasil change that uses it land in one pull request and one CI run.
- Extracting Brasil (or the apps) later is a `git filter-repo` on `src/TrustFrameworks/Brazil/` (or `src/Apps/`) and its tests, plus switching `ProjectReference` to `PackageReference`. No API redesign is needed.
- Some Core APIs became public for extension authors and are now under compatibility rules.
- Cross-implementation evidence that interop and fuzzing used to provide is gone. Conformance relies on unit tests with independent vectors (ADR 0016), `SimpleSign.Contracts.Tests`, and manual checks with external validators (for example ITI VALIDAR, see `docs/articles/icp-brasil-validar-check.md`).
- Contributors and agents read one instruction file, `CLAUDE.md`.

**Alternatives considered:**

| Approach | Pros | Cons | Verdict |
|---|---|---|---|
| **Three repositories** (libraries, Brasil, apps) | Clean public image; independent releases | Publish-then-bump cycle for every cross-cutting change; three CI setups for one maintainer | Rejected for now |
| **Two repositories** (libraries + Brasil, apps) | Apps' heavy toolchain (Avalonia, Node) leaves the library repository | Same cycle for the CLI, which tracks library features closely | Rejected for now |
| **Single repository with enforced boundaries (chosen)** | One change, one PR; split stays cheap | Repository still hosts apps with their own toolchains | **Chosen** |
| **Keep everything as it was** | No work | Core coupled to one country; maintenance cost of unused tooling | Rejected |
