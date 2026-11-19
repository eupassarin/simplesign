# ADR 0030: CLI Extensions

**Status:** Accepted.

**Context:**
The `simplesign` command line knew every trust framework by name. `--profile iofe`, the `iofe` policy presets,
`--tsl-profile iofe` and, later, the `iofe` commands of INDECOPI's accreditation guide were code inside
`SimpleSign.Cli`, next to the same things for ICP-Brasil, Gov.br and eIDAS. Three consequences:

- A framework's material was scattered: its library under one folder, its command-line part in the CLI, its
  documentation, playbook and generator in three more places. Nothing could be handed over, reviewed or extracted
  as "the Peruvian part".
- Every user of the CLI carried every framework, and adding one meant a release of the CLI.
- The CLI project referenced each framework package, so the dependency pointed from the generic tool to the
  specific frameworks.

The library already had the right shape (ADR 0009, ADR 0029: `ICountryExtension`, `TrustProfile`). The tool did not.

**Decision:**

- **`src/TrustFrameworks` becomes `src/Extensions`**, and a framework's folder holds everything that is its own: its
  packages, its CLI extension, its documentation, its playbooks and their generator. Peru (IOFE) is the first laid
  out this way: `src/Extensions/Peru/Iofe/{SimpleSign.Peru.Iofe,
  SimpleSign.Peru.Iofe.Cli, docs, playbooks, tools}`. Package, assembly and namespace names do not change.
- **The CLI has an extension contract**, `SimpleSign.Cli.Extensibility` (`ICliExtension`): an extension adds
  commands (Spectre.Console.Cli), trust profiles (`--profile`), signing and validation policies by name
  (`--signing-policy`, `--policy`, `policy export --preset`) and trusted-list profiles (`--tsl-profile`). The three
  static catalogs of the CLI (`CliProfiles`, `PolicyPresets`, `TrustedListProfiles`) are registries: the CLI's own
  entries plus those of the extensions in use. A name the CLI already has is never replaced by an extension.
- **Extensions are installed after the CLI**, not compiled into it:
  `simplesign extension install PACKAGE [--version V] [--source URL|FOLDER]`, `extension list`,
  `extension remove NAME`. An extension is a NuGet package with a `cli-extension/` folder — an `extension.json`
  manifest (`name`, `assembly`, `type`, `contract`, `minCliVersion`, `version`, `package`) and the assemblies —
  extracted to `~/.simplesign/extensions/NAME` (`SIMPLESIGN_EXTENSIONS_DIR` replaces the folder). A distribution
  may also bundle extensions in `extensions/` next to the CLI; the TestBench does, for the CLI it runs.
- **Loading.** Each extension loads in its own `AssemblyLoadContext`, which takes from the CLI every assembly the
  CLI has (SimpleSign's packages, Spectre.Console, the contract) and from the extension's folder only what the CLI
  lacks. Both sides therefore see the same types, whatever version of them the extension was built with; the
  manifest's `contract` and `minCliVersion` say when that is not safe, and the CLI then refuses the extension with
  the reason. An extension that fails to load is reported on the error stream and left out: it never takes the
  command line down. The assemblies are loaded from a copy of their bytes, not mapped from the file: Windows does not
  let a loaded assembly's file be deleted, and `extension remove` and a new `extension install` are run by the very
  process that loaded the extension.
- **Peru moves out of the CLI.** `SimpleSign.Cli` no longer references `SimpleSign.Peru.Iofe`; the profile, the
  presets, the list profile and the `iofe` commands are `SimpleSign.Peru.Iofe.Cli`.
- **Then ICP-Brasil, Gov.br and eIDAS** (second round). The CLI references no trust framework: its own profile is
  `sandbox`, its own policies `default`, `strict` and `minimal`.
  - `SimpleSign.Europe.Eidas.Cli` (`eidas`): the profile and the two policies. Its folder is
    `src/Extensions/Europe/Eidas/{SimpleSign.Europe.Eidas, SimpleSign.Europe.Eidas.Cli, docs, playbooks, tools}`.
  - `SimpleSign.Brazil.Cli` (`brasil`), one extension for the two Brazilian frameworks, which share
    `SimpleSign.Brazil` and are used together: the `icp-brasil` and `gov-br` profiles, the `icp-brasil` and `govbr`
    policies, and what was Brazilian inside the standard commands. Its folder is
    `src/Extensions/Brazil/{SimpleSign.Brazil, IcpBrasil, GovBr, SimpleSign.Brazil.Cli, docs, playbooks, tools}`.
- **What was Brazilian inside `sign`, `validate`, `inspect` and `timestamp verify` needed more contract**, added as
  members with defaults so an extension written for the first round still loads (the contract stays version 1):
  - *A command that runs a standard one.* `simplesign brasil sign` is `sign` plus `--icp-policy`, `--aea`/`--cpf`
    and `--health-document`/`--registration`: `CliExtensionContext.SignAsync(CliSignRequest)` runs the standard
    `sign` on the rest of the line, with hooks to refuse the line (`Validate`), add to the signer (`Configure`) and
    to the stamp (`ConfigureAppearance`). `sign` is not copied, so every option and credential it has or gains is
    there. Spectre.Console.Cli hands a command only the tokens after `--` verbatim, so the command's form is
    `brasil sign [its options] -- [arguments of sign]`; `ICliExtension.PassThroughCommands` lets the CLI put a line
    typed in any order into that form before parsing it.
  - *Passive hooks*, applied by the standard commands whenever the extension is installed, with or without
    `--profile`: `ConfigureServices` (the roots of a framework as anchors of every validation),
    `CreateChainValidationProviders` (its chain rules in `validate` and `validate-dir`) and `Annotate` (a node in
    the tree and properties in the JSON of `validate` and `inspect`: `lei14063`, `brasil`, `manifest` keep their
    names).
  - `simplesign timestamp verify --icp` becomes `simplesign brasil timestamp verify`.
- **An option a command does not have is an error** in `sign` and `timestamp verify`. Spectre.Console.Cli drops
  unknown options in silence, which was harmless while `--icp-policy` was an option of `sign` and is not now: a
  script that still calls `sign --icp-policy ad-rt` would get a signature without the policy. The error names the
  command and the package that has the option.

**Consequences:**

- `simplesign … --profile iofe` (and `--signing-policy iofe`, `--policy iofe`, `--tsl-profile iofe`,
  `simplesign iofe …`) works only after `simplesign extension install SimpleSign.Peru.Iofe.Cli`; the same goes for
  `icp-brasil`, `gov-br`, `govbr` (`SimpleSign.Brazil.Cli`) and `eidas` (`SimpleSign.Europe.Eidas.Cli`). Without the
  extension the CLI names the package to install. This is a breaking change for scripts that used those names.
- Scripts that sign with Brazilian options change command: `simplesign sign … --icp-policy ad-rt` is
  `simplesign brasil sign … --icp-policy ad-rt` (`--brasil` is also `--aea` there), and `timestamp verify --icp` is
  `brasil timestamp verify`. Without the Brazilian extension, `validate` no longer applies the ICP-Brasil and Gov.br
  chain validation nor trusts their roots, and its JSON has no `lei14063`, `brasil` (they were `null` for other
  signatures) or, in `inspect`, `manifest`.
- `SimpleSign.Cli.Extensibility` now references `SimpleSign.PAdES` (the signer a pass-through command configures).
- Installing an extension is running its code with the user's rights at every start of `simplesign`. The install
  command accepts only an https source or a local folder or file, shows the package's SHA-512 and never updates by
  itself. It does not verify a package signature: the packages have no author signature yet (the open code-signing
  item); when they do, `install` should check it.
- The CLI is a framework-dependent .NET tool that already relies on reflection (Spectre.Console.Cli), so loading
  assemblies at run time costs nothing new. The Agent is Native AOT and cannot load plugins: if frameworks leave it,
  it will be by registration at compile time.
- The TestBench, the Agent and the Sandbox still know the frameworks directly (profile menu, kinds of signature,
  catalog, test fixtures shaped as INDECOPI's list). They were left as they are: the TestBench moves with
  `SimpleSign.Sandbox` to `src/Apps/Development`, apart from the applications end users run. The TestBench bundles
  the three extensions with the CLI it runs (`cli/extensions/`) and writes `brasil sign` lines for a signature under
  an ICP-Brasil policy.
- A framework that follows Peru's layout can be extracted with its history by `git filter-repo` on one folder.
