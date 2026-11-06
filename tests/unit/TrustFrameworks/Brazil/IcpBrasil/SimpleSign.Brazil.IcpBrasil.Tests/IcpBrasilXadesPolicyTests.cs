using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES;

namespace SimpleSign.Brazil.IcpBrasil.Tests;

/// <summary>XAdES signatures under the ICP-Brasil XML policies (LPA_XAdES).</summary>
[Trait("Category", "Unit")]
public sealed class IcpBrasilXadesPolicyTests
{
    private static readonly System.Security.Cryptography.X509Certificates.X509Certificate2 s_cert =
        TestCertificateFactory.CreateSelfSignedCert("CN=Fulano de Tal, O=ICP-Brasil");
    private static readonly byte[] s_xml = "<?xml version=\"1.0\"?><contrato><id>1</id></contrato>"u8.ToArray();

    [Fact]
    public async Task Validate_XadesAdRbWithCurrentPolicy_IsValid()
    {
        var policy = IcpBrasilSignaturePolicies.Current(IcpBrasilPolicy.AdRb, IcpBrasilPolicyFormat.Xades);
        var result = await SignAndRead(policy.ToReference());

        var check = IcpBrasilPolicyValidator.Validate(result.SignaturePolicy, result.SigningTime!.Value, hasSignatureTimestamp: false, IcpBrasilPolicyFormat.Xades);

        check.Status.ShouldBe(IcpBrasilPolicyStatus.Valid, string.Join("; ", check.Errors));
        check.Policy.ShouldNotBeNull().Oid.ShouldBe(policy.Oid);
    }

    [Fact]
    public async Task Validate_XadesWithWrongPolicyHash_IsInvalid()
    {
        var policy = IcpBrasilSignaturePolicies.Current(IcpBrasilPolicy.AdRb, IcpBrasilPolicyFormat.Xades);
        var result = await SignAndRead(policy.ToReference() with { Hash = new byte[32] });

        var check = IcpBrasilPolicyValidator.Validate(result.SignaturePolicy, result.SigningTime!.Value, hasSignatureTimestamp: false);

        check.Status.ShouldBe(IcpBrasilPolicyStatus.Invalid);
        check.Errors.ShouldContain(e => e.Contains("sigPolicyHash", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Validate_XadesAdRtWithoutTimestamp_IsInvalid()
    {
        var policy = IcpBrasilSignaturePolicies.Current(IcpBrasilPolicy.AdRt, IcpBrasilPolicyFormat.Xades);
        var result = await SignAndRead(policy.ToReference());

        var check = IcpBrasilPolicyValidator.Validate(result.SignaturePolicy, result.SigningTime!.Value, hasSignatureTimestamp: false);

        check.Status.ShouldBe(IcpBrasilPolicyStatus.Invalid);
        check.Errors.ShouldContain(e => e.Contains("timestamp", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Validate_XadesPolicyCheckedAsPades_ReportsFormatMismatch()
    {
        var policy = IcpBrasilSignaturePolicies.Current(IcpBrasilPolicy.AdRb, IcpBrasilPolicyFormat.Xades);
        var result = await SignAndRead(policy.ToReference());

        var check = IcpBrasilPolicyValidator.Validate(result.SignaturePolicy, result.SigningTime!.Value, hasSignatureTimestamp: false, IcpBrasilPolicyFormat.Pades);

        check.Status.ShouldBe(IcpBrasilPolicyStatus.Invalid);
    }

    [Fact]
    public void Validate_NullReference_IsNone() =>
        IcpBrasilPolicyValidator.Validate(null, DateTimeOffset.UtcNow, hasSignatureTimestamp: false)
            .Status.ShouldBe(IcpBrasilPolicyStatus.None);

    private static async Task<XadesValidationResult> SignAndRead(SignaturePolicyReference reference)
    {
        byte[] signed = await XadesSigner.Document(s_xml).WithCertificate(s_cert).WithSignaturePolicy(reference).SignAsync();
        var result = new XadesSignatureValidator(new ValidationOptions { CheckRevocation = false }).Validate(signed, trustAnchors: [s_cert]);
        result.IsValid.ShouldBeTrue(string.Join("; ", result.Errors));
        return result;
    }
}
