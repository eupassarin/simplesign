# CLI Extensions

The `simplesign` command line comes with the formats, the general policies and the trust frameworks it has always
had (ICP-Brasil, Gov.br, eIDAS, the Sandbox). Anything else is an **extension**: a package installed into a CLI that
is already there, which adds commands and entries to the lists the standard commands read.

## Installing

```bash
dotnet tool install --global SimpleSign.Cli
simplesign extension install SimpleSign.Peru.Iofe.Cli          # the latest stable version, from nuget.org
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
the IOFE one for the CLI it runs); `extension remove` does not touch those.

> **An extension is code.** It runs with your rights every time `simplesign` starts. Install only packages you
> trust. `install` takes a package only over https or from your disk and never updates by itself; it does not
> verify a package signature.

## What an extension adds

| | Where it shows |
|---|---|
| Commands | Its own branch, e.g. `simplesign iofe sign` |
| Trust profiles | `--profile NAME`, `--trust-profile NAME`, `simplesign profiles` |
| Signing policies | `--signing-policy NAME`, `simplesign policy export signing --preset NAME` |
| Validation policies | `--policy NAME`, `simplesign policy export validation --preset NAME` |
| Trusted-list profiles | `--tsl-profile NAME` |

A name the CLI already has (`default`, `strict`, `eidas`, `sandbox`…) is never replaced by an extension.

Without the extension, a name it would add is unknown, and the CLI says how to get it:

```text
$ simplesign validate contrato.pdf --profile iofe
Unknown profile 'iofe': use sandbox, eidas, icp-brasil, gov-br. The profiles of other trust frameworks come with
extensions: 'simplesign extension install PACKAGE'.
```

## Extensions

| Package | Name | Adds |
|---|---|---|
| `SimpleSign.Peru.Iofe.Cli` | `iofe` | Peru (IOFE): `--profile iofe`, the `iofe` and `iofe-agent` policies, `--tsl-profile iofe`, `simplesign iofe sign\|verify\|view` — see [IOFE](../../src/Extensions/Peru/Iofe/docs/iofe.md) |

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
- `CliProfileContext` tells a profile whether it is loaded to sign or to validate (an expired trusted list is refused
  for signing and kept for validation, where the policy judges it) and the `--sandbox` URL, when there is one.
- Read `CliExtensionContext.HttpClientProvider` when a command runs: it is the CLI's client, with `--allow-origin`,
  `--allow-ldap`, `--tls-trust` and the proxy applied.

### The package

The package carries the extension in a `cli-extension/` folder: the assemblies and an `extension.json`.

```json
{ "name": "my-framework", "assembly": "My.Extension.dll", "type": "My.Extension.MyExtension",
  "contract": 1, "minCliVersion": "0.12.0", "version": "1.0.0", "package": "My.Extension" }
```

| Field | |
|---|---|
| `name` | The folder the extension is installed in, and what `extension remove` takes |
| `assembly`, `type` | The file and the full name of the `ICliExtension` type; it needs a public parameterless constructor |
| `contract` | `CliExtensionContract.Version` of the contract it was built against; the CLI loads only its own |
| `minCliVersion` | The oldest CLI it runs in |
| `version`, `package` | Shown by `extension list` |

`src/Extensions/Peru/Iofe/SimpleSign.Peru.Iofe.Cli/SimpleSign.Peru.Iofe.Cli.csproj` is a working example: it targets
the CLI's framework (net8.0), writes the manifest at build from the package version, and packs its build output under
`cli-extension/`.

The CLI gives an extension its own copy of every assembly it has (SimpleSign's packages, Spectre.Console, the
contract) and loads from the extension's folder only what it lacks, so ship your own dependencies and do not count on
a newer SimpleSign than the CLI's: state the CLI you need in `minCliVersion`.

To try an extension without packing it, point `SIMPLESIGN_EXTENSIONS_DIR` at a folder that holds
`<name>/extension.json` and the build output, or pack it and `extension install My.Extension --source ./nupkg`.

The design is in [ADR 0030](../adr/0030-cli-extensions.md).
