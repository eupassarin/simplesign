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
  out this way: `src/Extensions/Peru/Iofe/{SimpleSign.Peru.Iofe, SimpleSign.Peru.Iofe.Accredited,
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
  command line down.
- **Peru moves out of the CLI.** `SimpleSign.Cli` no longer references `SimpleSign.Peru.Iofe`; the profile, the
  presets, the list profile and the `iofe` commands are `SimpleSign.Peru.Iofe.Cli`. ICP-Brasil, Gov.br and eIDAS
  stay built in for now and can move the same way.

**Consequences:**

- `simplesign … --profile iofe` (and `--signing-policy iofe`, `--policy iofe`, `--tsl-profile iofe`,
  `simplesign iofe …`) works only after `simplesign extension install SimpleSign.Peru.Iofe.Cli`. Without it the CLI
  says the profile is unknown and how to get it. This is a breaking change for scripts that used those names.
- Installing an extension is running its code with the user's rights at every start of `simplesign`. The install
  command accepts only an https source or a local folder or file, shows the package's SHA-512 and never updates by
  itself. It does not verify a package signature: the packages have no author signature yet (the open code-signing
  item); when they do, `install` should check it.
- The CLI is a framework-dependent .NET tool that already relies on reflection (Spectre.Console.Cli), so loading
  assemblies at run time costs nothing new. The Agent is Native AOT and cannot load plugins: if frameworks leave it,
  it will be by registration at compile time.
- The TestBench, the Agent and the Sandbox still know IOFE directly (profile menu, catalog, test fixtures shaped as
  INDECOPI's list). They were left as they are: the TestBench moves with `SimpleSign.Sandbox` to
  `src/Apps/Development`, apart from the applications end users run.
- A framework that follows Peru's layout can be extracted with its history by `git filter-repo` on one folder.
