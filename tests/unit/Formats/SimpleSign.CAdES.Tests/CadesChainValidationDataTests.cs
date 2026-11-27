using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.CAdES.Tests;

/// <summary>
/// <c>ValidateAsync</c> asks the trust frameworks' chain validation for its data (region, certificate type, signer,
/// metadata), without revocation and without changing the verdict.
/// </summary>
[Trait("Category", "Unit")]
public sealed class CadesChainValidationDataTests : IDisposable
{
    private readonly X509Certificate2 _cert = TestCertificateFactory.CreateSelfSignedCert();
    private readonly byte[] _data = "chain data"u8.ToArray();

    public void Dispose() => _cert.Dispose();

    private static CadesSignatureValidator Validator(RecordingChainValidationProvider provider) =>
        new(new ValidationOptions { CheckRevocation = false, ChainValidationProviders = [provider] });

    [Fact]
    public async Task ValidateAsync_Provider_ResultCarriesItsData()
    {
        var provider = new RecordingChainValidationProvider();
        byte[] cms = await CadesSigner.Document(_data).WithCertificate(_cert).SignAsync();

        var result = await Validator(provider).ValidateAsync(cms, _data, [_cert]);

        result.Indication.ShouldBe(SignatureIndication.Valid);
        result.ChainValidationRegion.ShouldBe("TEST");
        result.PolicyLevel.ShouldBe("A1");
        result.SignerId.ShouldBe("12345678909");
        result.SignerIdType.ShouldBe("CPF");
        result.ChainValidationMetadata.ShouldNotBeNull()["TEST.Key"].ShouldBe("value");
        provider.Asked.ShouldNotBeNull().CheckRevocation.ShouldBeFalse();
        provider.Asked.Signature.ShouldNotBeNull();
    }

    [Fact]
    public async Task ValidateAsync_ProviderRefuses_IsAWarningAndTheVerdictStays()
    {
        byte[] cms = await CadesSigner.Document(_data).WithCertificate(_cert).SignAsync();

        var result = await Validator(new RecordingChainValidationProvider(trusted: false)).ValidateAsync(cms, _data, [_cert]);

        result.Indication.ShouldBe(SignatureIndication.Valid);
        result.Warnings.ShouldContain("[TEST] not a test certificate");
        result.Errors.ShouldNotContain(e => e.Contains("not a test certificate", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ValidateAllAsync_Provider_EverySignerCarriesItsData()
    {
        byte[] cms = await CadesSigner.Document(_data).WithCertificate(_cert).SignAsync();

        var report = await Validator(new RecordingChainValidationProvider()).ValidateAllAsync(cms, _data, [_cert]);

        report.Signers.ShouldHaveSingleItem().Result.ChainValidationRegion.ShouldBe("TEST");
    }

    [Fact]
    public async Task Validate_Sync_DoesNotAskTheProvider()
    {
        var provider = new RecordingChainValidationProvider();
        byte[] cms = await CadesSigner.Document(_data).WithCertificate(_cert).SignAsync();

        var result = Validator(provider).Validate(cms, _data, [_cert]);

        result.ChainValidationRegion.ShouldBeNull();
        provider.Asked.ShouldBeNull();
    }
}
