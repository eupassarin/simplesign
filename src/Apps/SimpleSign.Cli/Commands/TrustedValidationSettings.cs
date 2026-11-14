using System.ComponentModel;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Policies;
using SimpleSign.XAdES.TrustedLists;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

/// <summary>The validation options shared by the validate commands: policy, trust store, trusted list, language.</summary>
internal class TrustedValidationSettings : CommonSettings
{
    /// <summary>Validation policy (JSON).</summary>
    [CommandOption("--policy <PATH>")]
    [Description("Validation policy: a JSON file (root ValidationConstraints) or a built-in name (default, strict, iofe, eidas, icp-brasil, govbr). Write one with 'simplesign policy export validation [[--preset NAME]]'")]
    public string? PolicyPath { get; init; }

    /// <summary>The trust profile: its validation policy (unless --policy) and its trust (unless --tsl/--lotl).</summary>
    [CommandOption("--profile <NAME>")]
    [Description("Trust profile: sandbox, iofe, icp-brasil or gov-br. Sets the validation policy (unless --policy) and the trust (unless --tsl or --lotl); see 'simplesign profiles'")]
    public string? Profile { get; init; }

    /// <summary>Profiles whose trust is added (their policies are not used).</summary>
    [CommandOption("--trust-profile <NAME>")]
    [Description("Also trust what this profile trusts (repeatable, e.g. --profile icp-brasil --trust-profile gov-br); the policy stays --profile's")]
    public string[] TrustProfiles { get; init; } = [];

    /// <summary>A running SimpleSign Sandbox (its origins are also allowed).</summary>
    [CommandOption("--sandbox <URL>")]
    [Description("A running SimpleSign Sandbox: its origins, LDAP and HTTPS chain are allowed; --profile sandbox trusts it, and --profile iofe reads its list instead of INDECOPI's")]
    public string? Sandbox { get; init; }

    /// <summary>Certificate the policy must be signed with (detached CMS next to it, .p7s).</summary>
    [CommandOption("--policy-signer <PATH>")]
    [Description("Certificate the policy must be signed with; its detached signature is <policy>.p7s")]
    public string? PolicySignerPath { get; init; }

    /// <summary>How much of each signature is validated.</summary>
    [CommandOption("--level <LEVEL>")]
    [Description("How much is validated: basic (signature and chain), timestamps, lt (plus revocation and long-term data) or lta (plus archive timestamps; the default)")]
    public string? Level { get; init; }

    /// <summary>Which revocation source is asked first.</summary>
    [CommandOption("--revocation-strategy <STRATEGY>")]
    [Description("ocsp-first (the default) or crl-first")]
    public string? RevocationStrategy { get; init; }

    /// <summary>Do not trust the operating system's roots.</summary>
    [CommandOption("--no-system-roots")]
    [Description("Do not trust the operating system's roots: only --trust, --trust-dir and the trusted lists")]
    public bool NoSystemRoots { get; init; }

    /// <summary>Check the revocation of chains that do not reach a trust anchor.</summary>
    [CommandOption("--revocation-for-untrusted")]
    [Description("Also check the revocation of chains that do not reach a trust anchor (off by default)")]
    public bool RevocationForUntrusted { get; init; }

    /// <summary>Write the ETSI TS 119 102-2 validation report (XML) to this file.</summary>
    [CommandOption("--etsi-report <PATH>")]
    [Description("Write the ETSI TS 119 102-2 signature validation report (XML) to this file")]
    public string? EtsiReportPath { get; init; }

    /// <summary>Write the simple report (JSON) to this file.</summary>
    [CommandOption("--simple-report <PATH>")]
    [Description("Write the simple report (JSON: indication, sub-indication, signer, times, policy per signature) to this file")]
    public string? SimpleReportPath { get; init; }

    /// <summary>Write the readable report (HTML) to this file.</summary>
    [CommandOption("--html-report <PATH>")]
    [Description("Write a readable report (HTML): result, integrity, signing time, signer certificate and public key per signature")]
    public string? HtmlReportPath { get; init; }

    /// <summary>The language of the HTML report.</summary>
    [CommandOption("--report-language <CODE>")]
    [Description("Language of the HTML report: en (default), pt or es")]
    public string? ReportLanguage { get; init; }

    /// <summary>Writes the reports asked with <see cref="EtsiReportPath"/>, <see cref="SimpleReportPath"/> and <see cref="HtmlReportPath"/>.</summary>
    internal void WriteReports(IReadOnlyList<SimpleSign.Core.Validation.SignatureReportEntry> entries)
    {
        if (EtsiReportPath is not null)
        {
            File.WriteAllText(EtsiReportPath, SimpleSign.Core.Validation.ValidationReports.ToEtsiXml(entries, ValidationLevel));
        }

        if (SimpleReportPath is not null)
        {
            File.WriteAllText(SimpleReportPath, SimpleSign.Core.Validation.ValidationReports.ToSimpleJson(entries));
        }

        if (HtmlReportPath is not null)
        {
            File.WriteAllText(HtmlReportPath, SimpleSign.Core.Validation.ValidationReports.ToHtml(entries, ReportLanguage));
        }
    }

    /// <summary>The validation level of <see cref="Level"/>.</summary>
    internal SimpleSign.Core.Validation.ValidationLevel ValidationLevel => Level?.ToLowerInvariant() switch
    {
        "basic" => SimpleSign.Core.Validation.ValidationLevel.BasicSignatures,
        "timestamps" => SimpleSign.Core.Validation.ValidationLevel.Timestamps,
        "lt" => SimpleSign.Core.Validation.ValidationLevel.LongTermData,
        _ => SimpleSign.Core.Validation.ValidationLevel.ArchivalData,
    };

    /// <summary>The verifier options of the revocation options.</summary>
    internal SimpleSign.Core.Validation.VerifierOptions Verifier => new()
    {
        RevocationStrategy = string.Equals(RevocationStrategy, "crl-first", StringComparison.OrdinalIgnoreCase)
            ? SimpleSign.Core.Validation.RevocationStrategy.CrlFirst
            : SimpleSign.Core.Validation.RevocationStrategy.OcspFirst,
        CheckRevocationForUntrustedChains = RevocationForUntrusted,
    };

    /// <summary>Folder of trust anchor certificates.</summary>
    [CommandOption("--trust-dir <DIR>")]
    [Description("Folder of trust anchor certificates (.cer, .crt, .der, .pem)")]
    public string? TrustDirectory { get; init; }

    /// <summary>Certificate the trust folder's manifest must be signed with.</summary>
    [CommandOption("--trust-dir-signer <PATH>")]
    [Description("Certificate the trust folder's manifest.json must be signed with")]
    public string? TrustDirectorySignerPath { get; init; }

    /// <summary>Trusted list (URL or file).</summary>
    [CommandOption("--tsl <URL|PATH>")]
    [Description("Trusted list (ETSI TS 119 612 / TS 102 231), URL or file; its CA and TSA services become trust anchors")]
    public string? TrustedList { get; init; }

    /// <summary>Certificate the trusted list must be signed with.</summary>
    [CommandOption("--tsl-signer <PATH>")]
    [Description("Certificate the trusted list must be signed with (the scheme operator's)")]
    public string? TrustedListSignerPath { get; init; }

    /// <summary>Which services of <c>--tsl</c> become anchors.</summary>
    [CommandOption("--tsl-profile <NAME>")]
    [Description("Which services of --tsl become anchors: default (CA and TSA services) or iofe (INDECOPI's list: its 'unspecified' TSAs too, never a code-signing certificate; an expired list is kept for the policy's TLNotExpired to judge)")]
    public string? TrustedListProfile { get; init; }

    /// <summary>A list of trusted lists (LOTL); its national lists become trust anchors.</summary>
    [CommandOption("--lotl <URL>")]
    [Description("List of trusted lists (LOTL, e.g. https://ec.europa.eu/tools/lotl/eu-lotl.xml): the CA and TSA services of the national lists it points to become trust anchors")]
    public string? Lotl { get; init; }

    /// <summary>Certificate the LOTL must be signed with.</summary>
    [CommandOption("--lotl-signer <PATH>")]
    [Description("Certificate the LOTL must be signed with (for the EU LOTL, one the Official Journal publishes)")]
    public string? LotlSignerPath { get; init; }

    /// <summary>Territories of the LOTL to load.</summary>
    [CommandOption("--lotl-territory <CODE>")]
    [Description("Load only this territory's list (repeatable, e.g. --lotl-territory PT --lotl-territory DE)")]
    public string[] LotlTerritories { get; init; } = [];

    /// <summary>Language of the verification report.</summary>
    [CommandOption("--lang <LANG>")]
    [Description("Language of the verification report: en (default) or es")]
    public string Language { get; init; } = "en";

    /// <summary>Whether the report is written in Spanish.</summary>
    public bool Spanish => Language.StartsWith("es", StringComparison.OrdinalIgnoreCase);

    /// <summary>Checks the files the options name.</summary>
    protected Spectre.Console.ValidationResult ValidateTrustOptions()
    {
        foreach (var (path, what) in new[]
        {
            (PolicyPath is not null && PolicyPresets.IsPreset(PolicyPresets.Validation, PolicyPath) ? null : PolicyPath, "Policy"), (PolicySignerPath, "Policy signer"), (TrustDirectorySignerPath, "Trust folder signer"),
            (TrustedListSignerPath, "Trusted list signer"),
            (LotlSignerPath, "LOTL signer"),
        })
        {
            if (path is not null && !File.Exists(path))
            {
                return Spectre.Console.ValidationResult.Error($"{what} file not found: {path}");
            }
        }

        if (Level is not null && Level.ToLowerInvariant() is not ("basic" or "timestamps" or "lt" or "lta"))
        {
            return Spectre.Console.ValidationResult.Error($"Unknown --level '{Level}': use basic, timestamps, lt or lta.");
        }

        if (RevocationStrategy is not null && RevocationStrategy.ToLowerInvariant() is not ("ocsp-first" or "crl-first"))
        {
            return Spectre.Console.ValidationResult.Error($"Unknown --revocation-strategy '{RevocationStrategy}': use ocsp-first or crl-first.");
        }

        if (TrustDirectory is not null && !Directory.Exists(TrustDirectory))
        {
            return Spectre.Console.ValidationResult.Error($"Trust folder not found: {TrustDirectory}");
        }

        if (Lotl is not null && (LotlSignerPath is null || !Uri.TryCreate(Lotl, UriKind.Absolute, out _)))
        {
            return Spectre.Console.ValidationResult.Error("--lotl needs a URL and --lotl-signer: the certificate the LOTL must be signed with.");
        }

        if (!TrustedListProfiles.IsKnown(TrustedListProfile))
        {
            return Spectre.Console.ValidationResult.Error($"Unknown --tsl-profile '{TrustedListProfile}': use {TrustedListProfiles.Names}.");
        }

        if (TrustedList is not null && TrustedListSignerPath is null && !TrustedListProfiles.IsIofe(TrustedListProfile))
        {
            return Spectre.Console.ValidationResult.Error("--tsl needs --tsl-signer: the certificate the list must be signed with (with --tsl-profile iofe, INDECOPI's bundled one is used).");
        }

        if (CliProfiles.Check(Profile, TrustProfiles, Sandbox, signing: false) is { } profileError)
        {
            return Spectre.Console.ValidationResult.Error(profileError);
        }

        return Language is "en" or "es" or "es-PE"
            ? Spectre.Console.ValidationResult.Success()
            : Spectre.Console.ValidationResult.Error($"Unknown language '{Language}': use en or es.");
    }

    /// <summary>The trusted lists <see cref="LoadTrustAsync"/> loaded, for the TrustedLists constraints.</summary>
    internal List<TrustedListInfo> LoadedTrustedLists { get; } = [];

    /// <summary>The trusted lists <see cref="LoadTrustAsync"/> loaded, as anchors at a time (their service history).</summary>
    internal List<ITimedTrustAnchorProvider> LoadedTimedAnchors { get; } = [];

    /// <summary>The profile's qualifiers (eIDAS): each signature's qualification, QESig, AdESig-QC…</summary>
    internal List<ISignatureQualifier> LoadedQualifiers { get; } = [];

    /// <summary>The policy, and the trust anchors of the trust folder and the trusted list.</summary>
    /// <param name="http">The CLI's HTTP provider (its proxy and outbound policy, <c>--allow-origin</c>): the trusted lists are downloaded through it.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    internal async Task<(ValidationPolicy Policy, List<X509Certificate2> Anchors)> LoadTrustAsync(SimpleSign.Core.Http.IHttpClientProvider? http, CancellationToken cancellationToken)
    {
        ValidationPolicy policy = PolicyPath is null ? ValidationPolicy.Default
            : PolicyPresets.IsPreset(PolicyPresets.Validation, PolicyPath) ? PolicyPresets.Validation[PolicyPath]()
            : PolicySignerPath is null ? ValidationPolicy.Load(PolicyPath)
            : ValidationPolicy.LoadSigned(PolicyPath, PolicyPath + ".p7s", LoadCertificate(PolicySignerPath));

        var anchors = new List<X509Certificate2>();

        // The trust profile: its policy unless --policy, its trust unless a trusted list is given explicitly.
        if (await CliProfiles.ResolveAsync(Profile, TrustProfiles, Sandbox, http ?? CliNetwork.Provider, cancellationToken) is { } profile)
        {
            if (PolicyPath is null)
            {
                policy = profile.ValidationPolicy;
            }

            LoadedQualifiers.AddRange(profile.SignatureQualifiers);
            if (TrustedList is null && Lotl is null)
            {
                anchors.AddRange(profile.TrustAnchorProviders.SelectMany(p => p.GetTrustAnchors()));
                LoadedTrustedLists.AddRange(profile.TrustAnchorProviders.OfType<ITrustedListInfoProvider>().SelectMany(p => p.TrustedLists));
                LoadedTimedAnchors.AddRange(profile.TrustAnchorProviders.OfType<ITimedTrustAnchorProvider>());
            }
        }
        if (TrustDirectory is not null)
        {
            var provider = new DirectoryTrustAnchorProvider(
                TrustDirectory, TrustDirectorySignerPath is null ? null : LoadCertificate(TrustDirectorySignerPath));
            anchors.AddRange(provider.GetTrustAnchors());
            anchors.AddRange(provider.GetIntermediateCertificates());
        }

        // An expired list is kept: the TLNotExpired constraint of the policy judges it, as EU DSS does.
        if (TrustedList is not null)
        {
            var options = TrustedListProfiles.Options(TrustedListProfile, TrustedListSignerPath is null ? null : LoadCertificate(TrustedListSignerPath)) with { RejectExpired = false };
            bool iofe = TrustedListProfile is not null && TrustedListProfile.Equals("iofe", StringComparison.OrdinalIgnoreCase);

            try
            {
                var list = Uri.TryCreate(TrustedList, UriKind.Absolute, out var url) && url.Scheme is "http" or "https"
                    ? await SimpleSign.XAdES.TrustedLists.TrustedList.DownloadAsync(url, options, http, cancellationToken: cancellationToken)
                    : SimpleSign.XAdES.TrustedLists.TrustedList.Load(await File.ReadAllBytesAsync(TrustedList, cancellationToken), options);
                anchors.AddRange(list.GetTrustAnchors());
                LoadedTrustedLists.AddRange(list.TrustedLists);
                LoadedTimedAnchors.Add(list);
            }
            catch (System.Security.Cryptography.CryptographicException ex) when (iofe)
            {
                // A list not signed by INDECOPI gives no anchors: the signatures are INDETERMINATE, as with a LOTL's lists.
                Spectre.Console.AnsiConsole.MarkupLine($"[yellow]TSL:[/] {Spectre.Console.Markup.Escape($"{TrustedList}: {ex.Message} No anchor comes from it.")}");
            }
        }

        if (Lotl is not null)
        {
            var set = await SimpleSign.XAdES.TrustedLists.TrustedListSet.LoadAsync(new SimpleSign.XAdES.TrustedLists.TrustedListSetOptions
            {
                LotlLocation = new Uri(Lotl),
                LotlSignerCertificates = [LoadCertificate(LotlSignerPath!)],
                Territories = LotlTerritories,
                Services = new TrustedListOptions { RejectExpired = false },
            }, http, cancellationToken);
            anchors.AddRange(set.GetTrustAnchors());
            LoadedTrustedLists.AddRange(set.TrustedLists);
            LoadedTimedAnchors.Add(set);
            foreach (var problem in set.Problems)
            {
                Spectre.Console.AnsiConsole.MarkupLine($"[yellow]LOTL:[/] {Spectre.Console.Markup.Escape($"{problem.Territory} ({problem.Location}): {problem.Reason}")}");
            }
        }

        return (policy, anchors);
    }

    /// <summary>A chain revocation checker that downloads through the CLI's HTTP provider (proxy, outbound policy).</summary>
    internal SimpleSign.Core.Revocation.IChainRevocationChecker RevocationCheckerFor(SimpleSign.Core.Http.IHttpClientProvider http) =>
        new SimpleSign.Core.Revocation.ChainRevocationChecker(http.GetClient(), outboundPolicy: http.OutboundPolicy)
        {
            Strategy = Verifier.RevocationStrategy,
        };

    private static X509Certificate2 LoadCertificate(string path) =>
        new SimpleSign.Core.Validation.CertificateChainService().LoadCertsFromBytes(File.ReadAllBytes(path)).FirstOrDefault()
        ?? throw new InvalidDataException($"No certificate in {path}.");
}
