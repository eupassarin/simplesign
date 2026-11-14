using System.Security.Cryptography.X509Certificates;
using System.Text;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Signing;
using SimpleSign.TestBench.Localization;
using SimpleSign.TestBench.Runs;
using SimpleSign.TestBench.Sandbox;
using SimpleSign.TestBench.TrustFrameworks;
using SimpleSign.XAdES.TrustedLists;

namespace SimpleSign.TestBench.Signing;

/// <summary>Where the trust anchors of the checks made before signing come from.</summary>
public enum SigningTrustChoice
{
    /// <summary>The Sandbox's root, as a bare anchor.</summary>
    SandboxRoot,

    /// <summary>The Sandbox's trusted list (its CA and TSA services), checked against its operator's certificate.</summary>
    SandboxTrustedList,

}

/// <summary>
/// The controls of the signing policy that need more than the policy file: the trust anchors the signing certificate and
/// each TSA must chain to (<c>WithTrustAnchors</c>), the TSA certificate expected (<c>TimestampOptions.ExpectedTsaCertificate</c>)
/// and the audit trail (<c>WithAuditSink</c>). Shared by PAdES, CAdES and XAdES.
/// </summary>
public sealed record SigningControlsOptions
{
    /// <summary>The trust anchors before signing; empty for none.</summary>
    public IReadOnlyList<SigningTrustChoice> Trust { get; init; } = [];

    /// <summary>The id of the Sandbox certificate the TSA must sign with (e.g. <c>tsa</c>); null for any.</summary>
    public string? ExpectedTsa { get; init; }

    /// <summary>Whether each signature, made or refused, is recorded in an audit trail.</summary>
    public bool AuditLog { get; init; }

    /// <summary>The trust profile (Sign menu): its trust anchors are added; its policy is the one <c>signingPolicyId</c> names.</summary>
    public TrustProfileChoice Profile { get; init; }

    /// <summary>Which list the IOFE profile reads: INDECOPI's or the Sandbox's (test).</summary>
    public ProfileListSource ProfileSource { get; init; }

    /// <summary>Other profiles whose trust is added (their policies are not used).</summary>
    public IReadOnlyList<TrustProfileChoice> TrustProfiles { get; init; } = [];

    /// <summary>Whether a profile is chosen (its own, or another's trust).</summary>
    internal bool HasProfile => Profile != TrustProfileChoice.None || TrustProfiles.Count > 0;
}

/// <summary><see cref="SigningControlsOptions"/> turned into library objects, C# and CLI flags.</summary>
internal sealed class SigningControls
{
    /// <summary>The Sandbox root a CLI command reads for <c>--trust</c>.</summary>
    public const string TrustFile = "signing-trust.cer";

    /// <summary>The trusted list operator's certificate a CLI command reads for <c>--tsl-signer</c>.</summary>
    public const string TrustedListSignerFile = "tl-signer.pem";

    /// <summary>The expected TSA certificate a CLI command reads for <c>--expected-tsa</c>.</summary>
    public const string ExpectedTsaFile = "expected-tsa.cer";

    private readonly X509Certificate2? _root;
    private readonly string? _trustedListUrl;
    private readonly X509Certificate2? _trustedListSigner;
    private readonly SigningControlsOptions? _profile;
    private readonly string? _sandboxUrl;

    private SigningControls(
        IReadOnlyList<ITrustAnchorProvider> anchors, X509Certificate2? root, string? trustedListUrl, X509Certificate2? trustedListSigner,
        X509Certificate2? expectedTsa, string? expectedTsaId, RecordingAuditSink? audit, SigningControlsOptions? profile = null, string? sandboxUrl = null,
        IReadOnlyList<ITrustAnchorProvider>? profileAnchors = null)
    {
        _profile = profile is { HasProfile: true } ? profile : null;
        ProfileAnchors = profileAnchors ?? [];
        _sandboxUrl = sandboxUrl;
        Anchors = anchors;
        _root = root;
        _trustedListUrl = trustedListUrl;
        _trustedListSigner = trustedListSigner;
        ExpectedTsa = expectedTsa;
        ExpectedTsaId = expectedTsaId;
        Audit = audit;
    }

    /// <summary>No control: the builders are left as they are.</summary>
    public static SigningControls None { get; } = new([], null, null, null, null, null, null);

    /// <summary>The trust anchors for <c>WithTrustAnchors</c>: the form's and the profile's.</summary>
    public IReadOnlyList<ITrustAnchorProvider> Anchors { get; }

    /// <summary>The profile's trust anchors (what <c>WithProfile</c> adds).</summary>
    public IReadOnlyList<ITrustAnchorProvider> ProfileAnchors { get; }

    /// <summary>The anchors that are not the profile's (the form's own trust choices).</summary>
    public IReadOnlyList<ITrustAnchorProvider> OtherAnchors => [.. Anchors.Where(a => !ProfileAnchors.Contains(a))];

    /// <summary>The certificate the TSA must sign with, or null.</summary>
    public X509Certificate2? ExpectedTsa { get; }

    /// <summary>The Sandbox id of <see cref="ExpectedTsa"/>.</summary>
    public string? ExpectedTsaId { get; }

    /// <summary>The audit sink of the library run, or null.</summary>
    public RecordingAuditSink? Audit { get; }

    /// <summary>Reads the anchors, the expected TSA and the audit choice from the connected Sandbox.</summary>
    /// <param name="options">The options; null for none.</param>
    /// <param name="sandbox">The Sandbox connection.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <param name="profiles">The trust profiles; null for <see cref="ProfileTrust.Shared"/>.</param>
    public static async Task<SigningControls> ResolveAsync(SigningControlsOptions? options, SandboxEnvironment sandbox, CancellationToken cancellationToken,
        ProfileTrust? profiles = null)
    {
        if (options is null || (options.Trust.Count == 0 && options.ExpectedTsa is null && !options.AuditLog && !options.HasProfile))
        {
            return None;
        }

        var anchors = new List<ITrustAnchorProvider>();
        X509Certificate2? root = null;
        string? listUrl = null;
        X509Certificate2? listSigner = null;
        X509Certificate2? expected = null;
        IReadOnlyList<ITrustAnchorProvider> profileAnchors = [];
        if (options.HasProfile)
        {
            if (options.Profile == TrustProfileChoice.GovBr)
            {
                throw new ArgumentException(L.T("Gov.br signatures are made on Gov.br's service: its profile validates only."));
            }

            var profile = await (profiles ?? ProfileTrust.Shared).ResolveAsync(options.Profile, options.ProfileSource, options.TrustProfiles, sandbox, cancellationToken, signing: true)
                ?? throw new SigningException(L.T("The profile's trust could not be read: it has no anchors."), SigningErrorReason.UntrustedRoot);
            profileAnchors = profile.TrustAnchorProviders;
            anchors.AddRange(profileAnchors);
        }

        bool sandboxTrust = options.Trust.Any(t => t is SigningTrustChoice.SandboxRoot or SigningTrustChoice.SandboxTrustedList);
        if (sandboxTrust || options.ExpectedTsa is not null)
        {
            var connection = sandbox.Current ?? throw new ArgumentException(L.T("The trust anchors and the expected TSA come from the Sandbox: connect one."));
            var http = sandbox.GetClient();
            if (options.Trust.Contains(SigningTrustChoice.SandboxRoot))
            {
                root = connection.Root;
                anchors.Add(new FixedAnchors("Sandbox root", root));
            }

            if (options.Trust.Contains(SigningTrustChoice.SandboxTrustedList))
            {
                var lists = connection.Info.TrustedLists ?? throw new ArgumentException(L.T("This Sandbox publishes no trusted list."));
                listUrl = lists.TlUrl;
                listSigner = X509Certificate2.CreateFromPem(await http.GetStringAsync(new Uri(lists.TlSignerUrl), cancellationToken));
                try
                {
                    var listOptions = new TrustedListOptions { SignerCertificates = [listSigner] };
                    anchors.Add(await TrustedList.DownloadAsync(new Uri(listUrl), listOptions, sandbox, cancellationToken: cancellationToken));
                }
                catch (Exception ex) when (ex is InvalidDataException or System.Security.Cryptography.CryptographicException or HttpRequestException)
                {
                    throw new SigningException(L.T("The trusted list was refused: {0}", ex.Message), SigningErrorReason.UntrustedRoot, ex);
                }
            }

            if (options.ExpectedTsa is { } id)
            {
                expected = X509CertificateLoader.LoadCertificate(
                    await http.GetByteArrayAsync(new Uri(connection.Url, $"api/certificates/{Uri.EscapeDataString(id)}/cer"), cancellationToken));
            }
        }

        return new SigningControls(anchors, root, listUrl, listSigner, expected, options.ExpectedTsa, options.AuditLog ? new RecordingAuditSink() : null,
            options, sandbox.Current?.Url.AbsoluteUri, profileAnchors);
    }

    /// <summary>Whether the profile's own preset is the signing policy: the CLI then says <c>--profile</c> alone, without <c>--signing-policy</c>.</summary>
    public bool ProfileSetsPolicy(string? signingPolicyId) => ProfileSetsPolicy(_profile, signingPolicyId);

    /// <summary>Whether <paramref name="signingPolicyId"/> is the preset of the profile <paramref name="options"/> name.</summary>
    public static bool ProfileSetsPolicy(SigningControlsOptions? options, string? signingPolicyId) =>
        signingPolicyId is not null && options is { HasProfile: true } p && signingPolicyId == ProfileTrust.PolicyPresetId(p.Profile, Policies.PolicyViewer.Signing);

    /// <summary>The C# of the profile applied with its policy: <c>.WithProfile(profile)</c>.</summary>
    public string ProfileStepCode() =>
        $".WithProfile(profile) // {(_profile is { } p ? ProfileCode(p) : "")}: its signing policy and its trust anchors";

    /// <summary>
    /// The C# of the trust anchors, or null when there are none; with <paramref name="byProfile"/> the profile's are left
    /// to <see cref="ProfileStepCode"/>.
    /// </summary>
    public string? TrustCode(bool byProfile = false)
    {
        string[] parts =
        [
            .. _root is null ? Array.Empty<string>() : ["new DirectoryTrustAnchorProvider(\"trust\") /* the Sandbox root */"],
            .. _trustedListUrl is null ? Array.Empty<string>() : [$"await TrustedList.DownloadAsync(new Uri({SigningPlan.Str(_trustedListUrl)}), new TrustedListOptions {{ SignerCertificates = [tlSigner] }})"],
            .. _profile is { } p && !byProfile ? [$".. profile.TrustAnchorProviders /* {ProfileCode(p)} */"] : Array.Empty<string>(),
        ];
        return Anchors.Count == 0 || parts.Length == 0 ? null
            : ".WithTrustAnchors([" + string.Join(", ", parts) + "]) // the signing certificate and each TSA must chain to these anchors";
    }

    /// <summary>How the C# gets the profile.</summary>
    private static string ProfileCode(SigningControlsOptions p)
    {
        string create = p.Profile switch
        {
            TrustProfileChoice.Iofe when p.ProfileSource == ProfileListSource.Sandbox => "await IofeProfile.LoadAsync(new IofeExtensionOptions { TrustedListUrl = sandboxTl, TrustedListSigners = [tlSigner] })",
            TrustProfileChoice.Iofe => "await IofeProfile.LoadAsync()",
            TrustProfileChoice.Eidas when p.ProfileSource == ProfileListSource.Sandbox => "await EidasProfile.LoadAsync(new EidasExtensionOptions { LotlUrl = sandboxLotl, LotlSigners = [lotlSigner] })",
            TrustProfileChoice.Eidas => "await EidasProfile.LoadAsync()",
            TrustProfileChoice.IcpBrasil => "IcpBrasilProfile.Create()",
            TrustProfileChoice.Sandbox => "the Sandbox's LOTL as a TrustProfile",
            _ => "TrustProfile.Default",
        };
        return $"var profile = {create}" + string.Concat(p.TrustProfiles.Select(ProfileTrust.Name).OfType<string>().Select(n => $".WithTrustFrom({n})"));
    }

    /// <summary>The C# of the audit sink, or null.</summary>
    public string? AuditCode() =>
        Audit is null ? null : ".WithAuditSink(new JsonLinesAuditSink(\"audit.jsonl\")) // a hash-chained record of each signature";

    /// <summary>The C# of the expected TSA inside a <c>TimestampOptions</c> initializer, or null.</summary>
    public string? ExpectedTsaCode() =>
        ExpectedTsa is null ? null : "ExpectedTsaCertificate = X509CertificateLoader.LoadCertificateFromFile(\"expected-tsa.cer\"),";

    /// <summary>The CLI flags of the anchors and the audit trail.</summary>
    public void Cli(CliLine line)
    {
        if (_root is not null)
        {
            line.Add("--trust", TrustFile);
        }

        if (_trustedListUrl is not null)
        {
            line.Add("--tsl", _trustedListUrl, "--tsl-signer", TrustedListSignerFile);
        }

        if (_profile is { } p)
        {
            if (ProfileTrust.Name(p.Profile) is { } name)
            {
                line.Add("--profile", name);
            }

            foreach (string extra in p.TrustProfiles.Select(ProfileTrust.Name).OfType<string>().Distinct())
            {
                line.Add("--trust-profile", extra);
            }

            if (p.Profile == TrustProfileChoice.Sandbox || p.TrustProfiles.Contains(TrustProfileChoice.Sandbox)
                || (p.Profile is TrustProfileChoice.Iofe or TrustProfileChoice.Eidas && p.ProfileSource == ProfileListSource.Sandbox))
            {
                line.Add("--sandbox", _sandboxUrl ?? "http://localhost:5300/");
            }
        }

        if (Audit is not null)
        {
            line.Add("--audit-log", CliExecutor.AuditFile);
        }
    }

    /// <summary>The CLI flag of the expected TSA (with the signature TSA's flags).</summary>
    public void CliTimestamp(CliLine line)
    {
        if (ExpectedTsa is not null)
        {
            line.Add("--expected-tsa", ExpectedTsaFile);
        }
    }

    /// <summary>The files the CLI flags name.</summary>
    public IEnumerable<KeyValuePair<string, byte[]>> CliFiles()
    {
        if (_root is not null)
        {
            yield return new(TrustFile, _root.RawData);
        }

        if (_trustedListSigner is not null)
        {
            yield return new(TrustedListSignerFile, Encoding.ASCII.GetBytes(_trustedListSigner.ExportCertificatePem() + "\n"));
        }

        if (ExpectedTsa is not null)
        {
            yield return new(ExpectedTsaFile, ExpectedTsa.RawData);
        }
    }

    /// <summary>
    /// Writes the audit records of the run to its log: those the library run recorded, or the trail the CLI wrote, with
    /// the result of its hash-chain check.
    /// </summary>
    /// <param name="cliTrail">The audit file the CLI wrote, or null for a library run.</param>
    public void Report(byte[]? cliTrail)
    {
        if (RunLog.Current is not { } log || Audit is null)
        {
            return;
        }

        if (cliTrail is null)
        {
            foreach (var e in Audit.Events)
            {
                log.Note(RunStages.Finish, L.T("Audit: {0}", Describe(e)), warning: !e.Signed);
            }

            return;
        }

        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, cliTrail);
            foreach (string line in File.ReadLines(path).Where(l => l.Length > 0))
            {
                log.Note(RunStages.Finish, L.T("Audit: {0}", line));
            }

            int broken = JsonLinesAuditSink.Verify(path);
            log.Note(RunStages.Finish, broken == 0 ? L.T("Audit trail: the hash chain holds.") : L.T("Audit trail: broken at line {0}.", broken), warning: broken != 0);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static string Describe(SignatureAuditEvent e) =>
        $"{e.Format} {(e.Signed ? "signed" : "refused")} — {e.CertificateSubject} (serial {e.CertificateSerialNumber})"
        + (e.Reason is { } reason ? $", reason {reason}" : "")
        + (e.OutputSha256 is { } hash ? $", output SHA-256 {hash}" : "")
        + $", policy {e.PolicyName}";

    private sealed class FixedAnchors(string name, X509Certificate2 root) : ITrustAnchorProvider
    {
        public string RegionCode => "SANDBOX";

        public string DisplayName => name;

        public IReadOnlyList<X509Certificate2> GetTrustAnchors() => [root];
    }
}

/// <summary>An audit sink that keeps the records of one run in memory.</summary>
internal sealed class RecordingAuditSink : ISignatureAuditSink
{
    private readonly List<SignatureAuditEvent> _events = [];

    /// <summary>The records, in order.</summary>
    public IReadOnlyList<SignatureAuditEvent> Events
    {
        get
        {
            lock (_events)
            {
                return [.. _events];
            }
        }
    }

    /// <inheritdoc />
    public ValueTask RecordAsync(SignatureAuditEvent auditEvent, CancellationToken cancellationToken)
    {
        lock (_events)
        {
            _events.Add(auditEvent);
        }

        return ValueTask.CompletedTask;
    }
}
