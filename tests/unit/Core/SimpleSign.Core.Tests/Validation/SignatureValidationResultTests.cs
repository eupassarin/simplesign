using Shouldly;
using SimpleSign.Core.Validation;
using Xunit;

namespace SimpleSign.Core.Tests.Validation;

[Trait("Category", "Unit")]
public sealed class SignatureValidationResultTests
{
    [Theory]
    [InlineData(RevocationSource.None, SignatureIndication.Valid)]
    [InlineData(RevocationSource.EmbeddedCrl, SignatureIndication.Valid)]
    [InlineData(RevocationSource.EmbeddedOcsp, SignatureIndication.Valid)]
    [InlineData(RevocationSource.OnlineCrl, SignatureIndication.Valid)]
    [InlineData(RevocationSource.OnlineOcsp, SignatureIndication.Valid)]
    [InlineData(RevocationSource.Indeterminate, SignatureIndication.Indeterminate)]
    public void Indication_NoEstablishedRevocation_DistinguishesUnknownStatus(
        RevocationSource source,
        SignatureIndication expected)
    {
        var result = new SignatureValidationResult
        {
            IsIntegrityValid = true,
            IsSignatureValid = true,
            IsCertificateChainValid = true,
            IsNotRevoked = true,
            RevocationSource = source
        };

        result.Indication.ShouldBe(expected);
    }

    [Theory]
    [InlineData(true, RevocationSource.Indeterminate)]
    [InlineData(false, RevocationSource.EmbeddedOcsp)]
    public void Indication_TrustWarning_DoesNotOverrideUnknownOrRevokedStatus(bool notRevoked, RevocationSource source)
    {
        var result = new SignatureValidationResult
        {
            IsIntegrityValid = true,
            IsSignatureValid = true,
            IsChainTrustWarning = true,
            IsNotRevoked = notRevoked,
            RevocationSource = source
        };

        result.Indication.ShouldBe(source == RevocationSource.Indeterminate
            ? SignatureIndication.Indeterminate
            : SignatureIndication.Invalid);
    }

    [Fact]
    public void Indication_ChainCannotBeBuilt_ReturnsIndeterminate()
    {
        var result = new SignatureValidationResult
        {
            IsIntegrityValid = true,
            IsSignatureValid = true,
            IsCertificateChainValid = false,
            IsNotRevoked = true
        };

        result.Indication.ShouldBe(SignatureIndication.Indeterminate);
    }

    [Fact]
    public void Indication_CryptographicSignatureFails_ReturnsInvalid()
    {
        var result = new SignatureValidationResult
        {
            IsIntegrityValid = true,
            IsSignatureValid = false,
            IsCertificateChainValid = true,
            IsNotRevoked = true
        };

        result.Indication.ShouldBe(SignatureIndication.Invalid);
    }

    [Fact]
    public void Indication_ConfirmedRevocation_ReturnsInvalid()
    {
        var result = new SignatureValidationResult
        {
            IsIntegrityValid = true,
            IsSignatureValid = true,
            IsCertificateChainValid = true,
            IsNotRevoked = false,
            RevocationSource = RevocationSource.EmbeddedOcsp
        };

        result.Indication.ShouldBe(SignatureIndication.Invalid);
    }

    [Fact]
    public void Indication_CmsCannotBeParsed_ReturnsIndeterminate()
    {
        var result = new SignatureValidationResult
        {
            IsIntegrityValid = false,
            IsSignatureValid = false,
            Indication = SignatureIndication.Indeterminate
        };

        result.Indication.ShouldBe(SignatureIndication.Indeterminate);
    }

    [Fact]
    public void Indication_SignatureVerificationCannotBeCompleted_ReturnsIndeterminate()
    {
        var result = new SignatureValidationResult
        {
            IsIntegrityValid = true,
            IsSignatureValid = false,
            IsSignatureVerificationIndeterminate = true
        };

        result.Indication.ShouldBe(SignatureIndication.Indeterminate);
    }

    [Fact]
    public void Indication_UntrustedDocumentTimestamp_ReturnsIndeterminate()
    {
        var result = new SignatureValidationResult
        {
            IsIntegrityValid = true,
            IsSignatureValid = true,
            IsCertificateChainValid = false,
            IsChainTrustWarning = true,
            IsNotRevoked = true,
            IsDocumentTimestamp = true,
            IsTsaTrusted = false
        };

        result.Indication.ShouldBe(SignatureIndication.Indeterminate);
    }

    [Fact]
    public void Indication_InvalidTimestampIntegrityRemainsInvalid()
    {
        var result = new SignatureValidationResult
        {
            IsIntegrityValid = false,
            IsSignatureValid = true,
            IsChainTrustWarning = true,
            IsDocumentTimestamp = true,
            IsTsaTrusted = false
        };

        result.Indication.ShouldBe(SignatureIndication.Invalid);
    }
}
