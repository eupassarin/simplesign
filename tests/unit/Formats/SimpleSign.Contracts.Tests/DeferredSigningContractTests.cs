using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.CAdES;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES;
using Xunit;

namespace SimpleSign.Contracts.Tests;

/// <summary>
/// Two-phase (deferred) signing, the same in PAdES, CAdES and XAdES: the deferred builder takes the options
/// of the one-call builder, phase one hands out the bytes to sign with a session, a builder resumed from the
/// session bytes completes the signature, and a changed session, a wrong signature and a refusal of the
/// signing policy are treated alike.
/// </summary>
[Trait("Category", "Contract")]
public sealed class DeferredSigningContractTests
{
    private static readonly byte[] s_key = RandomNumberGenerator.GetBytes(32);

    // ── The deferred builder takes the options of the one-call builder ────

    /// <summary>
    /// The options of a one-call builder that its deferred builder does not take, with the reason. A new option
    /// of a one-call builder fails this test until it is added to the deferred builder or listed here.
    /// </summary>
    private static readonly Dictionary<Type, string[]> s_notDeferred = new()
    {
        // The key signs on another machine between the phases: the deferred builder takes the public certificate.
        [typeof(PadesSignerBuilder)] = ["WithExternalSigner", "WithCertificateFile"],
        [typeof(CadesSignerBuilder)] = ["WithExternalSigner"],
        [typeof(XadesSignerBuilder)] = ["WithExternalSigner"],
    };

    [Theory]
    [InlineData(typeof(PadesSignerBuilder), typeof(DeferredSignerBuilder))]
    [InlineData(typeof(CadesSignerBuilder), typeof(CadesDeferredSignerBuilder))]
    [InlineData(typeof(XadesSignerBuilder), typeof(XadesDeferredSignerBuilder))]
    public void DeferredBuilder_TakesEveryOptionOfTheOneCallBuilder(Type oneCall, Type deferred)
    {
        var deferredOptions = Options(deferred).Select(Signature).ToHashSet(StringComparer.Ordinal);

        var missing = Options(oneCall)
            .Where(m => !s_notDeferred[oneCall].Contains(m.Name))
            .Select(Signature)
            .Where(signature => !deferredOptions.Contains(signature))
            .ToList();

        missing.ShouldBeEmpty($"{deferred.Name} lacks options of {oneCall.Name}");
        Options(deferred).ShouldAllBe(m => m.ReturnType == deferred);

        // What the country packages read from a builder to pick a policy (the signer, its chain, the extensions).
        var deferredProperties = deferred.GetProperties(BindingFlags.Public | BindingFlags.Instance).Select(p => $"{p.PropertyType} {p.Name}").ToList();
        oneCall.GetProperties(BindingFlags.Public | BindingFlags.Instance).Select(p => $"{p.PropertyType} {p.Name}")
            .ShouldBeSubsetOf(deferredProperties);
    }

    private static IEnumerable<MethodInfo> Options(Type builder) =>
        builder.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Where(m => m.Name.StartsWith("With", StringComparison.Ordinal) || m.Name.StartsWith("As", StringComparison.Ordinal));

    private static string Signature(MethodInfo method) =>
        $"{method.Name}{(method.IsGenericMethod ? "<>" : string.Empty)}({string.Join(", ", method.GetParameters().Select(p => p.ParameterType.ToString()))})";

    // ── Prepare, resume from the session bytes, complete ──────────────────

    [Theory]
    [InlineData("pades", false)]
    [InlineData("cades", false)]
    [InlineData("xades", false)]
    [InlineData("pades", true)]
    [InlineData("cades", true)]
    [InlineData("xades", true)]
    public async Task PrepareResumeComplete_ProducesASignatureThatValidates(string format, bool timestamped)
    {
        using var signer = ContractFixtures.CreateSignerCertificate();
        using var publicCertificate = RemoteKey.PublicOnly(signer);
        using var tsaClient = ContractFixtures.BuildMockTsaClient();
        var profile = timestamped
            ? AdesBaselineProfile.Timestamped(new TimestampOptions(new Uri("http://mock-tsa.example.com")))
            : AdesBaselineProfile.Basic();

        Prepared prepared = await Prepare(format, publicCertificate, profile);
        byte[] signature = RemoteKey.Sign(signer, prepared.Request);
        byte[] signed = await Complete(format, [.. prepared.SessionData], signature, tsaClient);

        prepared.Request.PayloadKind.ShouldBe(format == "xades"
            ? ExternalSigningPayloadKind.XmlCanonicalizedSignedInfo
            : ExternalSigningPayloadKind.CmsSignedAttributes);
        prepared.Request.OperationId.ShouldBe("contract-op");
        (bool valid, bool hasTimestamp) = await Validate(format, signed, signer);
        valid.ShouldBeTrue();
        hasTimestamp.ShouldBe(timestamped);
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task Resume_SessionChangedOrAnotherKey_ThrowsCryptographicException(string format)
    {
        using var signer = ContractFixtures.CreateSignerCertificate();
        using var publicCertificate = RemoteKey.PublicOnly(signer);
        Prepared prepared = await Prepare(format, publicCertificate, AdesBaselineProfile.Basic());

        // The operation id is in every session; changing it leaves well-formed JSON with a stale HMAC.
        byte[] changed = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(prepared.SessionData).Replace("contract-op", "contract-xx", StringComparison.Ordinal));

        changed.ShouldNotBe(prepared.SessionData);
        Should.Throw<CryptographicException>(() => Resume(format, changed, s_key));
        Should.Throw<CryptographicException>(() => Resume(format, prepared.SessionData, RandomNumberGenerator.GetBytes(32)));
        Should.Throw<ArgumentException>(() => Resume(format, prepared.SessionData, new byte[16]));
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task Complete_SignatureOfAnotherKey_IsRefusedBeforeTheSignatureIsAssembled(string format)
    {
        using var signer = ContractFixtures.CreateSignerCertificate();
        using var other = ContractFixtures.CreateSignerCertificate("CN=Another Key, O=Tests");
        using var publicCertificate = RemoteKey.PublicOnly(signer);
        using var tsaClient = ContractFixtures.BuildMockTsaClient();
        var audit = new RecordingAuditSink();
        Prepared prepared = await Prepare(format, publicCertificate, AdesBaselineProfile.Basic());

        var ex = await Should.ThrowAsync<SigningException>(
            () => Complete(format, prepared.SessionData, RemoteKey.Sign(other, prepared.Request), tsaClient, audit));

        ex.Reason.ShouldBe(SigningErrorReason.ExternalSignerReturnedInvalidSignature);
        SignatureAuditEvent refused = audit.Events.ShouldHaveSingleItem();
        refused.Signed.ShouldBeFalse();
        refused.Reason.ShouldBe(SigningErrorReason.ExternalSignerReturnedInvalidSignature);
        refused.OperationId.ShouldBe("contract-op");
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task Prepare_RefusalOfTheSigningPolicy_IsAuditedAndNothingIsHandedOut(string format)
    {
        using var pki = new SyntheticPki();
        using var publicLeaf = RemoteKey.PublicOnly(pki.Leaf);
        var audit = new RecordingAuditSink();

        // The policy asks for a chain to a given anchor and none is given.
        var ex = await Should.ThrowAsync<SigningException>(() => Prepare(
            format, publicLeaf, AdesBaselineProfile.Basic(), [pki.IntermediateCa], TestPolicies.SigningWithTrustAnchor, audit));

        SignatureAuditEvent refused = audit.Events.ShouldHaveSingleItem();
        refused.Signed.ShouldBeFalse();
        refused.Reason.ShouldBe(ex.Reason);
        refused.Reason.ShouldNotBeNull();
        refused.OperationId.ShouldBe("contract-op");
        refused.PolicyName.ShouldBe(TestPolicies.SigningWithTrustAnchor.Name);
        refused.CertificateSubject.ShouldBe(pki.Leaf.Subject);
    }

    [Theory]
    [InlineData("pades")]
    [InlineData("cades")]
    [InlineData("xades")]
    public async Task Complete_Success_IsAuditedWithTheOperationIdOfPhaseOne(string format)
    {
        using var signer = ContractFixtures.CreateSignerCertificate();
        using var publicCertificate = RemoteKey.PublicOnly(signer);
        using var tsaClient = ContractFixtures.BuildMockTsaClient();
        var audit = new RecordingAuditSink();
        Prepared prepared = await Prepare(format, publicCertificate, AdesBaselineProfile.Basic());

        byte[] signed = await Complete(format, prepared.SessionData, RemoteKey.Sign(signer, prepared.Request), tsaClient, audit);

        SignatureAuditEvent completed = audit.Events.ShouldHaveSingleItem();
        completed.Signed.ShouldBeTrue();
        completed.OperationId.ShouldBe("contract-op");
        completed.AchievedLevel.ShouldBe(AdesBaselineLevel.Basic);
        completed.OutputSha256.ShouldBe(Convert.ToHexString(SHA256.HashData(signed)));
    }

    // ── helpers ───────────────────────────────────────────────────────────

    private sealed record Prepared(byte[] SessionData, ExternalSigningRequest Request);

    private static async Task<Prepared> Prepare(
        string format,
        X509Certificate2 publicCertificate,
        AdesBaselineProfile profile,
        IReadOnlyList<X509Certificate2>? chain = null,
        SimpleSign.Core.Policies.SigningPolicy? policy = null,
        ISignatureAuditSink? audit = null)
    {
        chain ??= [];
        policy ??= SimpleSign.Core.Policies.SigningPolicy.Default;
        switch (format)
        {
            case "pades":
                {
                    var builder = DeferredSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage())
                        .WithCertificate(publicCertificate, chain).WithSessionIntegrityKey(s_key)
                        .WithLevel(profile).WithSigningPolicy(policy).WithOperationId("contract-op");
                    var prepared = await (audit is null ? builder : builder.WithAuditSink(audit)).PrepareAsync();
                    return new Prepared(prepared.SessionData, prepared.ToSigningRequest());
                }

            case "cades":
                {
                    var builder = CadesDeferredSigner.Document(ContractFixtures.BinaryContent)
                        .WithCertificate(publicCertificate, chain).WithSessionIntegrityKey(s_key)
                        .WithLevel(profile).WithSigningPolicy(policy).WithOperationId("contract-op");
                    var prepared = await (audit is null ? builder : builder.WithAuditSink(audit)).PrepareAsync();
                    return new Prepared(prepared.SessionData, prepared.ToSigningRequest());
                }

            default:
                {
                    var builder = XadesDeferredSigner.Document(ContractFixtures.XmlDocument)
                        .WithCertificate(publicCertificate, chain).WithSessionIntegrityKey(s_key)
                        .WithLevel(profile).WithSigningPolicy(policy).WithOperationId("contract-op");
                    var prepared = await (audit is null ? builder : builder.WithAuditSink(audit)).PrepareAsync();
                    return new Prepared(prepared.SessionData, prepared.ToSigningRequest());
                }
        }
    }

    private static object Resume(string format, byte[] sessionData, byte[] key) => format switch
    {
        "pades" => DeferredSigner.Resume(sessionData, key),
        "cades" => CadesDeferredSigner.Resume(sessionData, key),
        _ => XadesDeferredSigner.Resume(sessionData, key),
    };

    private static Task<byte[]> Complete(
        string format, byte[] sessionData, byte[] signature, HttpClient http, ISignatureAuditSink? audit = null)
    {
        var provider = new SimpleSign.Core.Http.SingleClientProvider(http);
        switch (format)
        {
            case "pades":
                {
                    var builder = DeferredSigner.Resume(sessionData, s_key).WithHttpClientProvider(provider);
                    return (audit is null ? builder : builder.WithAuditSink(audit)).CompleteAsync(signature);
                }

            case "cades":
                {
                    var builder = CadesDeferredSigner.Resume(sessionData, s_key).WithHttpClientProvider(provider);
                    return (audit is null ? builder : builder.WithAuditSink(audit)).CompleteAsync(signature);
                }

            default:
                {
                    var builder = XadesDeferredSigner.Resume(sessionData, s_key).WithHttpClientProvider(provider);
                    return (audit is null ? builder : builder.WithAuditSink(audit)).CompleteAsync(signature);
                }
        }
    }

    private static async Task<(bool Valid, bool HasTimestamp)> Validate(string format, byte[] signed, X509Certificate2 signer)
    {
        switch (format)
        {
            case "pades":
                {
                    using var stream = new MemoryStream(signed);
                    var results = await new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false, TrustedRoots = [signer] })
                        .ValidateAsync(stream);
                    return (results[0].IsSignatureValid && results[0].IsIntegrityValid, results[0].HasValidTimestamp == true);
                }

            case "cades":
                {
                    var result = new CadesSignatureValidator().Validate(signed, ContractFixtures.BinaryContent, [signer]);
                    return (result.IsValid, result.HasValidTimestamp == true);
                }

            default:
                {
                    var result = new XadesSignatureValidator().Validate(signed, [signer]);
                    return (result.IsValid, result.HasValidSignatureTimeStamp == true);
                }
        }
    }
}
