using System.Text.Json;
using Shouldly;
using SimpleSign.TestBench.Cades;
using SimpleSign.TestBench.CrossValidation;
using SimpleSign.TestBench.Runs;
using SimpleSign.TestBench.Sandbox;
using SimpleSign.TestBench.Signing;
using SimpleSign.TestBench.Xml;
using Xunit.Abstractions;

namespace SimpleSign.TestBench.Tests;

/// <summary>
/// Signs every Sandbox scenario (each signer, TSA and failure, in PAdES, CAdES and XAdES, at each level
/// that can be produced) and validates it with SimpleSign and with the EU DSS under the same validation
/// policy (SimpleSign's default, written as the DSS constraint.xml): the indication and the sub-indication
/// of every signature must be the same. The differences that are known and explained are listed in
/// <see cref="KnownDifferences"/>. Skipped when no DSS answers at <c>SIMPLESIGN_DSS_URL</c>
/// (start one with <c>tools/dss/docker-compose.yml</c>) or no Sandbox is connected.
/// </summary>
[Collection(TestBenchCollection.Name)]
[Trait("Category", "Integration")]
public sealed class DssScenarioCrossValidationTests(TestBenchFixture fixture, ITestOutputHelper output)
{
    /// <summary>A signing policy that refuses nothing, so that certificates a validator must reject can still sign.</summary>
    private const string PermissiveSigningPolicy = """
        {"SigningConstraints":{"Name":"Permissive (cross-validation)",
          "SigningCertificate":{"NotExpired":{"Level":"IGNORE"},"RevocationDataAvailable":{"Level":"IGNORE"},"KeyUsage":{"Level":"IGNORE","Id":["digitalSignature","nonRepudiation"]},"NotRevoked":{"Level":"IGNORE"}},
          "CACertificate":{"NotExpired":{"Level":"IGNORE"},"RevocationDataAvailable":{"Level":"IGNORE"},"NotRevoked":{"Level":"IGNORE"}},
          "Cryptographic":{"Level":"IGNORE","AcceptableEncryptionAlgo":{"Algo":["RSA","RSASSA-PSS","ECDSA"]},
            "MiniPublicKeySize":{"Algo":[{"Value":"RSA","Size":1024},{"Value":"RSASSA-PSS","Size":1024},{"Value":"ECDSA","Size":256}]},
            "AcceptableDigestAlgo":{"Algo":["SHA256","SHA384","SHA512"]}}}}
        """;

    /// <summary>
    /// Scenarios where SimpleSign and DSS 6.3 disagree for a known reason (a scenario id, or its prefix
    /// before the format). Each must say why; the test only reports them.
    /// </summary>
    private static readonly Dictionary<string, string> KnownDifferences = new(StringComparer.Ordinal)
    {
        // The OCSP responder answers "unknown" while the CRL, valid and fresh, says good. SimpleSign falls back to the
        // CRL (TOTAL_PASSED); DSS keeps the latest data, the "unknown" answer, and stops there (INDETERMINATE/
        // CERTIFICATE_CHAIN_GENERAL_FAILURE). An "unknown" answer is not acceptable revocation data, and the CRL is.
        ["fault:ocsp-unknown"] = "SimpleSign uses the valid CRL when OCSP answers unknown; DSS does not",

        // A certificate issued on demand, expired by validation time. EN 319 102-1 §5.2.6: an expired signing certificate
        // with no proof of existence is OUT_OF_BOUNDS_NO_POE, which SimpleSign gives; DSS looked at the revocation data
        // first (CERTIFICATE_CHAIN_GENERAL_FAILURE) while the Sandbox's OCSP responder answered "unknown" for it. It now
        // answers good for the short-lived certificates it issues, so DSS may agree: remove this entry once a run with
        // DSS shows no difference (until then it does no harm: an entry that no longer differs is never reported).
        ["sample:expired"] = "SimpleSign reports the expiry (OUT_OF_BOUNDS_NO_POE); DSS may stop at the revocation data",
    };

    private static readonly string[] Signers =
    [
        "rsa-2048", "rsa-3072", "rsa-4096", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521", "no-nonrepudiation", "rsa-1024",
        "no-signing-key-usage", "good-ocsp", "good-crl-https", "good-crl-ldap", "under-expired-ca",
    ];

    /// <summary>Signers whose B-LT and B-LTA cannot be produced: the library refuses to embed the data of a revoked chain.</summary>
    private static readonly string[] RevokedSigners = ["revoked", "revoked-ocsp", "revoked-crl-https", "revoked-crl-ldap", "under-revoked-ca"];

    private static readonly string[] Formats = [RunFormats.Pades, RunFormats.Cades, RunFormats.Xades];

    private static readonly BaselineLevel[] AllLevels = [BaselineLevel.BB, BaselineLevel.BT, BaselineLevel.BLT, BaselineLevel.BLTA];

    /// <summary>The Sandbox failures, switched on while the scenario signs and validates.</summary>
    private static readonly Dictionary<string, SandboxFaults> Faults = new(StringComparer.Ordinal)
    {
        ["ocsp-delegated"] = new(OcspSigner: OcspSigner.Delegated),
        ["ocsp-unknown"] = new(Ocsp: OcspFault.Unknown),
        ["ocsp-unauthorized+crl-down"] = new(Ocsp: OcspFault.Unauthorized, Crl: CrlFault.Down),
        ["ocsp-down+crl-down"] = new(Ocsp: OcspFault.Down, Crl: CrlFault.Down),
        ["ocsp-expired+crl-expired"] = new(Ocsp: OcspFault.Expired, Crl: CrlFault.Expired),
        ["ocsp-down+crl-wrongkey"] = new(Ocsp: OcspFault.Down, Crl: CrlFault.WrongKey),
    };

    /// <summary>Faults under which B-LT cannot be produced: no usable revocation data to embed.</summary>
    private static readonly string[] FaultsWithoutLtv = ["ocsp-unauthorized+crl-down", "ocsp-down+crl-down", "ocsp-expired+crl-expired", "ocsp-down+crl-wrongkey"];

    private static readonly TsaProvider[] Tsas = [TsaProvider.SandboxUntrusted, TsaProvider.SandboxRevoked, TsaProvider.SandboxWrongName, TsaProvider.SandboxAuthenticated];

    /// <summary>Every scenario: kind:name|format|level.</summary>
    public static TheoryData<string> Scenarios()
    {
        var data = new TheoryData<string>();
        foreach (string format in Formats)
        {
            foreach (string signer in Signers)
            {
                // An LDAP CRL is not embedded: B-LT needs revocation data the signer can collect over HTTP.
                foreach (var level in signer == "good-crl-ldap" ? AllLevels[..2] : AllLevels)
                {
                    data.Add($"signer:{signer}|{format}|{level}");
                }
            }

            foreach (string signer in RevokedSigners)
            {
                foreach (var level in AllLevels[..2])
                {
                    data.Add($"signer:{signer}|{format}|{level}");
                }
            }

            foreach (var tsa in Tsas)
            {
                // A revoked TSA's token cannot be made B-LTA: the library refuses to embed a revoked chain.
                foreach (var level in tsa == TsaProvider.SandboxRevoked ? [BaselineLevel.BT] : new[] { BaselineLevel.BT, BaselineLevel.BLTA })
                {
                    data.Add($"tsa:{tsa}|{format}|{level}");
                }
            }

            foreach (string fault in Faults.Keys)
            {
                foreach (var level in FaultsWithoutLtv.Contains(fault) ? [BaselineLevel.BB] : new[] { BaselineLevel.BB, BaselineLevel.BLT })
                {
                    data.Add($"fault:{fault}|{format}|{level}");
                }
            }
        }

        return data;
    }

    [SkippableTheory]
    [MemberData(nameof(Scenarios))]
    public async Task Sign_Scenario_SimpleSignAndDssAgree(string scenario)
    {
        var dss = await ConnectAsync();
        string[] parts = scenario.Split('|');
        string kind = parts[0][..parts[0].IndexOf(':', StringComparison.Ordinal)];
        string name = parts[0][(kind.Length + 1)..];
        string format = parts[1];
        var level = Enum.Parse<BaselineLevel>(parts[2]);

        var faults = kind == "fault" ? Faults[name] : null;
        if (faults is not null)
        {
            await fixture.Sandbox.SetFaultsAsync(faults);
        }

        try
        {
            string signer = kind == "signer" ? name : "rsa-2048";
            var tsa = new TimestampChoice { Provider = kind == "tsa" ? Enum.Parse<TsaProvider>(name) : TsaProvider.Sandbox };
            var run = await fixture.Runs(dss).RunAsync(SignRequest(format, signer, level, tsa), default);

            run.Success.ShouldBeTrue($"{scenario} did not sign: {run.Error} {string.Join("; ", run.Issues.Select(i => i.Message))}");
            Compare(scenario, run);
        }
        finally
        {
            if (faults is not null)
            {
                await fixture.Sandbox.SetFaultsAsync(new SandboxFaults());
            }
        }
    }

    /// <summary>
    /// A failure of the Sandbox's trusted list (expired, signed by a certificate its LOTL does not name, changed after
    /// signing), seen by both validators: DSS downloads the list again within seconds (DSS_TL_REFRESH_SECONDS). Neither
    /// uses a list whose signature fails (TS 119 615); an expired list is left to TLNotExpired, a WARN.
    /// </summary>
    [SkippableTheory]
    [InlineData(TlFault.Expired)]
    [InlineData(TlFault.WrongSigner)]
    [InlineData(TlFault.Tampered)]
    public async Task Trust_TrustedListFault_SimpleSignAndDssAgree(TlFault fault)
    {
        var dss = await ConnectAsync();
        Skip.If(fixture.Sandbox.Current?.Info.TrustedLists is null, "The Sandbox publishes no trusted list.");
        await fixture.Sandbox.SetFaultsAsync(new SandboxFaults(TrustedList: fault));
        try
        {
            await WaitForTrustedListAsync(dss);
            var failures = new List<string>();
            foreach (string format in Formats)
            {
                string scenario = $"tl:{fault}|{format}|{BaselineLevel.BB}";
                var run = await fixture.Runs(dss).RunAsync(SignRequest(format, "rsa-2048", BaselineLevel.BB, new TimestampChoice()), default);
                run.Success.ShouldBeTrue($"{scenario} did not sign: {run.Error}");
                try
                {
                    Compare(scenario, run);
                }
                catch (ShouldAssertException ex)
                {
                    failures.Add(ex.Message);
                }
            }

            failures.ShouldBeEmpty();
        }
        finally
        {
            await fixture.Sandbox.SetFaultsAsync(new SandboxFaults());
            await WaitForTrustedListAsync(dss);
        }
    }

    [SkippableFact]
    public async Task Validate_Samples_SimpleSignAndDssAgree()
    {
        var dss = await ConnectAsync();
        var samples = fixture.ValidationSamples.Select(s => ($"sample:{s.Id}|{RunFormats.Pades}", s.FileId, (string?)null))
            .Concat(fixture.CadesSamples.Where(s => s.Kind == "validation").Select(s => ($"sample:{s.Id}|{RunFormats.Cades}", s.FileId, s.DataId)))
            .Concat(fixture.XmlSamples.Where(s => s.Kind == "validation").Select(s => ($"sample:{s.Id}|{RunFormats.Xades}", s.FileId, s.DataId)));
        var failures = new List<string>();
        foreach (var (scenario, fileId, dataId) in samples)
        {
            string format = scenario[(scenario.IndexOf('|', StringComparison.Ordinal) + 1)..];
            var request = new RunRequest(format, JsonSerializer.SerializeToElement(new ValidateOptions(fileId, dataId), WorkbenchJson.Options),
                CrossValidate: true, Kind: RunKinds.Validate);
            var run = await fixture.Runs(dss).RunAsync(request, default);
            try
            {
                Compare(scenario, run);
            }
            catch (ShouldAssertException ex)
            {
                failures.Add(ex.Message);
            }
        }

        failures.ShouldBeEmpty();
    }

    private RunRequest SignRequest(string format, string signer, BaselineLevel level, TimestampChoice tsa)
    {
        // Uploaded per run: the store forgets least recently used uploads past its limit.
        string policyId = fixture.UploadPolicy(PermissiveSigningPolicy, "permissive-signing-policy.json");
        object options = format switch
        {
            RunFormats.Pades => fixture.Options("contract", signer) with
            {
                Level = level,
                SigningPolicyId = policyId,
                Timestamp = tsa,
                ArchiveTimestamp = tsa,
            },
            RunFormats.Cades => new CadesOptions
            {
                DataId = fixture.CadesSamples.Single(s => s.Id == "text").FileId,
                CredentialId = fixture.Sandboxed(signer),
                Level = level,
                SigningPolicyId = policyId,
                Timestamp = tsa,
            },
            _ => new XmlOptions
            {
                DataId = fixture.XmlSamples.Single(s => s.Id == "order").FileId,
                CredentialId = fixture.Sandboxed(signer),
                Level = level,
                SigningPolicyId = policyId,
                Timestamp = tsa,
            },
        };
        return new RunRequest(format, JsonSerializer.SerializeToElement(options, options.GetType(), WorkbenchJson.Options), CrossValidate: true);
    }

    /// <summary>Lines up SimpleSign's signatures (countersignatures included) with DSS's, by signer, and compares them.</summary>
    private void Compare(string scenario, RunView run)
    {
        var comparison = run.CrossValidation.ShouldBeOfType<DssComparison>();
        comparison.Available.ShouldBeTrue(comparison.Error);
        var ours = Flatten(run.Validation).ToList();
        var theirs = comparison.Signatures.Where(s => s.Format is not null || s.SignedBy is not null).ToList();
        theirs.Count.ShouldBe(ours.Count, $"{scenario}: DSS found {theirs.Count} signature(s), SimpleSign {ours.Count}");

        var lines = new List<string>();
        foreach (var verdict in ours)
        {
            var match = theirs.FirstOrDefault(s => s.SignedBy == verdict.Signer) ?? theirs[0];
            theirs.Remove(match);
            string simpleSign = $"{Etsi(verdict.Indication)}/{verdict.SubIndication ?? "-"}";
            string dssVerdict = $"{Etsi(match.Indication)}/{match.SubIndication ?? "-"}";
            output.WriteLine($"{scenario} [{verdict.Signer}] SimpleSign {simpleSign}, DSS {dssVerdict}");
            if (simpleSign != dssVerdict)
            {
                lines.Add($"{scenario} [{verdict.Signer}]: SimpleSign {simpleSign} ({string.Join("; ", verdict.Errors)}), "
                    + $"DSS {dssVerdict} ({string.Join("; ", match.Errors)})");
            }
        }

        if (lines.Count == 0)
        {
            return;
        }

        string? known = KnownDifferences.Keys.FirstOrDefault(k => scenario == k || scenario.StartsWith(k + "|", StringComparison.Ordinal));
        if (known is not null)
        {
            output.WriteLine($"Known difference ({KnownDifferences[known]}): {string.Join(" / ", lines)}");
            return;
        }

        throw new ShouldAssertException(string.Join(Environment.NewLine, lines));
    }

    private static IEnumerable<RunVerdict> Flatten(IEnumerable<RunVerdict> verdicts) =>
        verdicts.SelectMany(v => (v.IsTimestamp ? Enumerable.Empty<RunVerdict>() : [v]).Concat(Flatten(v.Children)));

    /// <summary>Both validators' indications in ETSI's terms: TOTAL_PASSED, TOTAL_FAILED, INDETERMINATE.</summary>
    private static string Etsi(string indication) => indication.ToUpperInvariant() switch
    {
        "VALID" or "PASSED" or "TOTAL_PASSED" => "TOTAL_PASSED",
        "INVALID" or "FAILED" or "TOTAL_FAILED" => "TOTAL_FAILED",
        var other => other,
    };

    /// <summary>
    /// The DSS settings when a DSS answers; skips the test otherwise. When the Sandbox publishes a trusted list, waits
    /// (up to a minute) until DSS has loaded it, so the first validations do not run before DSS trusts the Sandbox.
    /// </summary>
    private async Task<DssSettings> ConnectAsync()
    {
        fixture.RequireSandbox();
        using var client = new DssClient(fixture.Documents);
        var settings = client.Settings with { Enabled = true };
        bool isDss = false;
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(4) };
            isDss = (await http.GetStringAsync(new Uri(settings.Url.TrimEnd('/') + "/services/"))).Contains("CXF", StringComparison.Ordinal);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or UriFormatException)
        {
        }

        Skip.IfNot(isDss, $"No DSS at {settings.Url}: docker compose -f tools/dss/docker-compose.yml up");
        if (fixture.Sandbox.Current?.Info.TrustedLists is { } lists)
        {
            for (int i = 0; i < 60 && !(await TrustedListSummaryAsync(settings)).Contains(lists.TlUrl, StringComparison.Ordinal); i++)
            {
                await Task.Delay(TimeSpan.FromSeconds(1));
            }
        }

        return settings;
    }

    /// <summary>Waits until DSS has downloaded the Sandbox's trusted list again (its "Last download attempt" changes), up to a minute.</summary>
    private async Task WaitForTrustedListAsync(DssSettings dss)
    {
        using var client = new DssClient(fixture.Documents) { Settings = dss };
        if (await client.WaitForTrustedListRefreshAsync(TimeSpan.FromMinutes(1), default) is { } why)
        {
            output.WriteLine(why);
        }
    }

    /// <summary>The text of the DSS "Trusted Lists Summary" page (tl-info), tags removed.</summary>
    private async Task<string> TrustedListSummaryAsync(DssSettings dss)
    {
        using var client = new DssClient(fixture.Documents) { Settings = dss };
        return await client.TrustedListSummaryAsync(default);
    }
}
