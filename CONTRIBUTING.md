# Contributing to SimpleSign

Thank you for your interest in contributing to SimpleSign! This document provides guidelines and instructions for contributing.

## Getting Started

### Prerequisites

- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) or later
- [.NET 10.0 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) (for full test matrix)
- Docker (optional, for the PKCS#11 tests)

### Building

```bash
git clone https://github.com/eupassarin/SimpleSign.git
cd simplesign
dotnet restore
dotnet build
```

### Running Tests

```bash
# Build the complete multi-target solution
dotnet build SimpleSign.sln

# Specific project
dotnet test tests/unit/SimpleSign.PAdES.Tests

# Cross-format signing contract
dotnet test tests/unit/SimpleSign.Contracts.Tests

# With coverage
dotnet test --collect:"XPlat Code Coverage" --settings coverlet.runsettings

# Network tests (TSA, OCSP, CRL)
dotnet test tests/integration/SimpleSign.Integration.Tests
```

## How to Contribute

### Reporting Bugs

Open an issue with:
- A clear title and description
- Steps to reproduce
- Expected vs actual behavior
- .NET version and OS

### Suggesting Features

Open an issue with the `enhancement` label. Describe:
- The use case
- Proposed API (if applicable)
- Any alternatives considered

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Run the tests of the projects you changed
5. Ensure the solution has no warnings (`dotnet build SimpleSign.sln` — warnings are errors)
6. Submit a pull request

### Code Style

- The project uses `TreatWarningsAsErrors=true` and `AnalysisMode=All`
- Nullable reference types are enabled globally
- Follow the existing immutable builder pattern for new signing APIs
- All public methods must have XML documentation (`<summary>`, `<param>`, `<returns>`)
- Async methods must accept `CancellationToken cancellationToken = default`
- Use `ConfigureAwait(false)` on all `await` calls in library code
- Prefer `[LoggerMessage]` source-generated logging over manual `ILogger` calls

### Test Guidelines

- Use xUnit `[Fact]` / `[Theory]` with behavior-oriented test names
- Use the assertion library already referenced by the target test project
- Tests requiring Docker, network or external TSA services must be explicitly categorized and skippable
- Cryptographic changes require positive and negative artifact tests; ADeS changes also require independent vectors when available
- Add `[Trait("Category", "...")]` for slow or network tests

### Commit Messages

Use clear, descriptive commit messages. Include a `Co-authored-by` trailer when applicable.

## Project Structure

```
src/
  SimpleSign.Core/           # CMS, TSA, OCSP, CRL, hashing, extension points
  SimpleSign.Pdf/            # PDF structure parsing and incremental save
  SimpleSign.PAdES/          # PAdES signing, validation, inspection
  SimpleSign.CAdES/          # CAdES signing and validation
  SimpleSign.XAdES/          # XAdES signing and validation
  SimpleSign.Signers.Pkcs11/ # tokens, smartcards, HSMs
  SimpleSign.Signers.Cloud/  # cloud certificates (PSC, CSC v2)
  SimpleSign.Brasil*/        # ICP-Brasil, Gov.br, fiscal XML
  SimpleSign.HtmlToPdf/      # HTML-to-PDF converter
  SimpleSign.Cli/            # dotnet tool
  SimpleSign.Agent/          # tray app with a local signing API
  SimpleSign.TestBench/      # local web app to try every option
  SimpleSign/                # meta-package
tests/
  unit/        # unit tests, one project per library
  integration/ # network-dependent tests
  cli/         # CLI tests
  smoke/       # NativeAOT smoke app
  shared/      # test helpers and fixtures
```

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
