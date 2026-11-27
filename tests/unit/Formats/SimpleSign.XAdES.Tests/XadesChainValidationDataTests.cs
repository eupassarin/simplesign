using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.XAdES.Tests;

/// <summary>
/// <c>ValidateAsync</c> and <c>ValidateAllAsync</c> ask the trust frameworks' chain validation for its data, without
/// revocation and without changing the verdict.
/// </summary>
[Trait("Category", "Unit")]
public sealed class XadesChainValidationDataTests : IDisposable
{
    private readonly X509Certificate2 _cert = TestCertificateFactory.CreateSelfSignedCert();
    private readonly byte[] _xml = "<doc><v>1</v></doc>"u8.ToArray();

    public void Dispose() => _cert.Dispose();

    private static XadesSignatureValidator Validator(RecordingChainValidationProvider provider) =>
        new(new ValidationOptions { CheckRevocation = false, ChainValidationProviders = [provider] });

    [Fact]
    public async Task ValidateAllAsync_Provider_ResultCarriesItsData()
    {
        var provider = new RecordingChainValidationProvider();
        byte[] signed = await XadesSigner.Document(_xml).WithCertificate(_cert).SignAsync();

        var result = (await Validator(provider).ValidateAllAsync(signed, [_cert])).ShouldHaveSingleItem();

        result.Indication.ShouldBe(SignatureIndication.Valid);
        result.ChainValidationRegion.ShouldBe("TEST");
        result.SignerId.ShouldBe("12345678909");
        result.ChainValidationMetadata.ShouldNotBeNull()["TEST.Key"].ShouldBe("value");
        provider.Asked.ShouldNotBeNull().CheckRevocation.ShouldBeFalse();
        provider.Asked.Xml.ShouldNotBeNull();
    }

    [Fact]
    public async Task ValidateAsync_ProviderRefuses_IsAWarningAndTheVerdictStays()
    {
        byte[] signed = await XadesSigner.Document(_xml).WithCertificate(_cert).SignAsync();

        var result = await Validator(new RecordingChainValidationProvider(trusted: false)).ValidateAsync(signed, [_cert]);

        result.Indication.ShouldBe(SignatureIndication.Valid);
        result.Warnings.ShouldContain("[TEST] not a test certificate");
    }
}
