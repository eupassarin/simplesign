# CLI Extensions

The `simplesign` command line comes with the formats (PAdES, CAdES, XAdES), the general policies and the profile of
a running Sandbox. A trust framework — ICP-Brasil and Gov.br, eIDAS, IOFE — is an **extension**: a package installed
into a CLI that is already there, which adds commands and entries to the lists the standard commands read.

## Installing

```bash
dotnet tool install --global SimpleSign.Cli
simplesign extension install SimpleSign.Brazil.Cli             # the latest stable version, from nuget.org
simplesign extension install SimpleSign.Europe.Eidas.Cli
simplesign extension install SimpleSign.Peru.Iofe.Cli
simplesign extension list
simplesign extension remove iofe
```

| Command | Does |
|---|---|
| `extension install <package>` | Downloads the package, shows where it came from and its SHA-512, and extracts the extension to your folder of extensions. `--version V` picks a version |
| `extension install <package> --source <folder>` | Takes the package from a folder of `.nupkg` files (offline, or a build of your own) |
| `extension install <package> --source <https url>` | Takes it from another NuGet v3 flat container |
| `extension install <file.nupkg>` | Installs that file |
| `extension list` | The installed extensions, what each adds, and why one was not loaded |
| `extension remove <name>` | Removes one from your folder |

Extensions live in `~/.simplesign/extensions/<name>/`; set `SIMPLESIGN_EXTENSIONS_DIR` to use another folder. A
copy of the CLI may also carry extensions in an `extensions/` folder next to `simplesign.dll` (the TestBench bundles
the three below for the CLI it runs); `extension remove` does not touch those.

> **An extension is code.** It runs with your rights every time `simplesign` starts. Install only packages you
> trust. `install` takes a package only over https or from your disk and never updates by itself; it does not
> verify a package signature.

## What an extension adds

| | Where it shows |
|---|---|
| Commands | Its own branch, e.g. `simplesign brasil timestamp verify` |
| Commands that run a standard one | `simplesign brasil sign` is `simplesign sign`, every option of it, plus the extension's own (`--icp-policy`…) |
| Trust profiles | `--profile NAME`, `--trust-profile NAME`, `simplesign profiles` |
| Signing policies | `--signing-policy NAME`, `simplesign policy export signing --preset NAME` |
| Validation policies | `--policy NAME`, `simplesign policy export validation --preset NAME` |
| Trusted-list profiles | `--tsl-profile NAME` |
| Chain validation and trust anchors | Every `validate` and `validate-dir`: a framework recognizes its own chains, with or without `--profile` |
| Notes about a signature | A node in the tree of `validate` and `inspect`, and properties in their `--json` (the Brazilian `lei14063`, `brasil`, `manifest`) |

A name the CLI already has (`default`, `strict`, `sandbox`, a property of its JSON…) is never replaced by an
extension.

Without the extension, a name it would add is unknown, and the CLI says how to get it — the package by name, for the
extensions published with SimpleSign:

```text
$ simplesign validate contrato.pdf --profile icp-brasil
Error: The profile 'icp-brasil' comes with an extension: 'simplesign extension install SimpleSign.Brazil.Cli'.

$ simplesign sign contrato.pdf --cert assinante.pfx --icp-policy ad-rt
Error: --icp-policy is an option of 'simplesign brasil sign', which comes with an extension: 'simplesign extension
install SimpleSign.Brazil.Cli'.
```

`sign` and `timestamp verify` refuse an option they do not have instead of dropping it, so a signature never goes out
without the policy that was asked for.

## Extensions

| Package | Name | Adds |
|---|---|---|
| `SimpleSign.Brazil.Cli` | `brasil` | Brazil: `--profile icp-brasil` and `gov-br`, the `icp-brasil` and `govbr` policies, `simplesign brasil sign` (`--icp-policy`, `--aea`, `--health-document`), `brasil timestamp verify`, and the ICP-Brasil and Gov.br chain validation, the Lei 14.063 level and the signer's manifest in `validate` and `inspect` — see [ICP-Brasil](../../src/Extensions/Brazil/docs/icp-brasil.md) |
| `SimpleSign.Europe.Eidas.Cli` | `eidas` | EU (eIDAS): `--profile eidas` (the EU LOTL, the qualification of each signature) and the `eidas` policies — see [eIDAS](../../src/Extensions/Europe/Eidas/docs/eidas.md) |
| `SimpleSign.Peru.Iofe.Cli` | `iofe` | Peru (IOFE): `--profile iofe`, the `iofe` and `iofe-agent` policies, `--tsl-profile iofe` — see [IOFE](../../src/Extensions/Peru/Iofe/docs/iofe.md). |

## Writing one

Reference `SimpleSign.Cli.Extensibility` and implement `ICliExtension`:

```csharp
public sealed class MyExtension : ICliExtension
{
    public string Name => "my-framework";
    public string Title => "My trust framework";

    private static CliExtensionContext s_context = null!;
    public void Initialize(CliExtensionContext context) => s_context = context;   // the CLI's HTTP client, its PIN prompt

    public void AddCommands(IConfigurator config) =>
        config.AddBranch("my-framework", branch => branch.AddCommand<CheckCommand>("check"));

    public IReadOnlyList<CliProfile> Profiles =>
    [
        new()
        {
            Name = "my-framework", Title = "My trust framework",
            SigningPolicy = "my-framework", ValidationPolicy = "my-framework", Trust = "my roots",
            LoadAsync = (context, cancellationToken) => MyProfile.LoadAsync(context.Http, context.Sandbox, cancellationToken),
        },
    ];

    public IReadOnlyDictionary<string, Func<SigningPolicy>> SigningPolicies =>
        new Dictionary<string, Func<SigningPolicy>> { ["my-framework"] = () => MyPolicies.Signing };

    public IReadOnlyDictionary<string, Func<ValidationPolicy>> ValidationPolicies =>
        new Dictionary<string, Func<ValidationPolicy>> { ["my-framework"] = () => MyPolicies.Validation };

    public IReadOnlyList<CliTrustedListProfile> TrustedListProfiles => [];
}
```

- Commands are [Spectre.Console.Cli](https://spectreconsole.net/cli/) commands, as the CLI's own.
- The members above are the ones every extension has. The rest have defaults, and an extension overrides what it
  needs: `PassThroughCommands`, `ConfigureServices`, `CreateChainValidationProviders`, `Annotate` (below).
- `CliProfileContext` tells a profile whether it is loaded to sign or to validate (an expired trusted list is refused
  for signing and kept for validation, where the policy judges it) and the `--sandbox` URL, when there is one.
- Read `CliExtensionContext.HttpClientProvider` when a command runs: it is the CLI's client, with `--allow-origin`,
  `--allow-ldap`, `--tls-trust` and the proxy applied.

### A command that runs `sign`

A framework that adds to a signature does not copy `sign`: its command takes its own options and hands the rest of
the line to the standard command, with what it adds.

```csharp
internal sealed class MySignCommand : AsyncCommand<MySignCommand.Settings>
{
    internal sealed class Settings : CommandSettings
    {
        [CommandOption("--my-policy <NAME>")]
        public string? Policy { get; init; }
    }

    public override Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken) =>
        s_context.SignAsync(new CliSignRequest
        {
            Arguments = [.. context.Remaining.Raw],                                   // the arguments of 'sign'
            Validate = sign => sign.SubFilter is null ? null : "--my-policy sets the sub-filter; remove --sub-filter.",
            Configure = (builder, sign, _) => ValueTask.FromResult(builder.WithMyPolicy(settings.Policy, sign.Timestamp)),
        }, cancellationToken);
}

// in the extension
public IReadOnlyList<CliPassThroughCommand> PassThroughCommands =>
    [new(["my-framework", "sign"], typeof(MySignCommand.Settings))];
```

- `CliSignRequest.Validate` refuses the line before anything is read; `Configure` gets the `PadesSignerBuilder` after
  the standard options were applied (level, field, metadata) and before the appearance, the signing policy and the
  audit sink; `ConfigureAppearance` changes the stamp of a visible signature. `CliSignOptions` is what `sign` read
  that such rules depend on (`--tsa` with its credentials, `--ltv`, `--sub-filter`, `--signer-name`…).
- What the command receives is `simplesign my-framework sign [its options] -- [arguments of sign]`. Declaring it in
  `PassThroughCommands` lets the user type both kinds of options in any order: the CLI moves the options of
  `Settings` to the front and adds the `--`. `--help` shows the extension's options; `simplesign sign --help` the rest.
- Every credential of `sign` works (`--cert`, `--pkcs11-lib`, `--psc-url`, `--csc-url`), and so does `--prepare`.

`SimpleSign.Brazil.Cli` (`BrasilSignCommand`) is the working example.

### What `validate` and `inspect` show

```csharp
public void ConfigureServices(IServiceCollection services) => services.AddMyFrameworkRoots();   // anchors of every validation

public IReadOnlyList<IChainValidationProvider> CreateChainValidationProviders(HttpClient http, ILogger? logger) =>
    new MyExtension(http, logger).ChainValidationProviders;                                    // the framework's chain rules

public IReadOnlyList<CliSignatureAnnotation> Annotate(CliSignatureFacts signature) =>
    signature.Validation is { ChainValidationRegion: "XX" } result
        ? [new() { Label = "My framework", Value = Level(result), Lines = [new("Holder", result.SignerId ?? "-")],
                   Json = new Dictionary<string, JsonElement> { ["myLevel"] = JsonSerializer.SerializeToElement(Level(result)) } }]
        : [];
```

`CliSignatureFacts.Validation` is null in `inspect`, which does not validate; `ManifestJson` and `CommitmentTypeOid`
come from the signature itself. An annotation is plain text (the CLI escapes it) and its JSON properties are added
to the signature's object, never over one the CLI writes.

### The package

The package carries the extension in a `cli-extension/` folder: the assemblies and an `extension.json`.

```json
{ "name": "my-framework", "assembly": "My.Extension.dll", "type": "My.Extension.MyExtension",
  "contract": 1, "minCliVersion": "0.13.0", "version": "1.0.0", "package": "My.Extension" }
```

| Field | |
|---|---|
| `name` | The folder the extension is installed in, and what `extension remove` takes |
| `assembly`, `type` | The file and the full name of the `ICliExtension` type; it needs a public parameterless constructor |
| `contract` | `CliExtensionContract.Version` of the contract it was built against; the CLI loads only its own |
| `minCliVersion` | The oldest CLI it runs in |
| `version`, `package` | Shown by `extension list` |

`src/Extensions/Peru/Iofe/SimpleSign.Peru.Iofe.Cli/SimpleSign.Peru.Iofe.Cli.csproj` is a working example. What makes
it an extension is in `src/Extensions/CliExtension.targets`, which the three extensions of this repository import: it
targets the CLI's framework (net8.0), writes the manifest at build from the package version and the project's
`CliExtensionName` and `CliExtensionType`, and packs the build output under `cli-extension/`.

The CLI gives an extension its own copy of every assembly it has (SimpleSign's packages, Spectre.Console, the
contract) and loads from the extension's folder only what it lacks, so ship your own dependencies and do not count on
a newer SimpleSign than the CLI's: state the CLI you need in `minCliVersion`.

To try an extension without packing it, point `SIMPLESIGN_EXTENSIONS_DIR` at a folder that holds
`<name>/extension.json` and the build output, or pack it and `extension install My.Extension --source ./nupkg`.

The design is in [ADR 0030](../adr/0030-cli-extensions.md).
