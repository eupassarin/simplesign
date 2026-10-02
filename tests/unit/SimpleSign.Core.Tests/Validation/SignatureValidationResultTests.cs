using Shouldly;
using SimpleSign.Core.Validation;
using Xunit;

namespace SimpleSign.Core.Tests.Validation;

public sealed class SignatureValidationResultTests
{
    [Theory]
    [InlineData(RevocationSource.None, true)]
    [InlineData(RevocationSource.EmbeddedCrl, true)]
    [InlineData(RevocationSource.EmbeddedOcsp, true)]
    [InlineData(RevocationSource.OnlineCrl, true)]
    [InlineData(RevocationSource.OnlineOcsp, true)]
    [InlineData(RevocationSource.Indeterminate, false)]
    public void IsValid_NoEstablishedRevocation_DistinguishesUnknownStatus(RevocationSource source, bool expected)
    {
        var result = new SignatureValidationResult
        {
            IsIntegrityValid = true,
            IsSignatureValid = true,
            IsCertificateChainValid = true,
            IsNotRevoked = true,
            RevocationSource = source
        };

        result.IsValid.ShouldBe(expected);
    }

    [Theory]
    [InlineData(true, RevocationSource.Indeterminate)]
    [InlineData(false, RevocationSource.EmbeddedOcsp)]
    public void IsValid_TrustWarning_DoesNotOverrideUnknownOrRevokedStatus(bool notRevoked, RevocationSource source)
    {
        var result = new SignatureValidationResult
        {
            IsIntegrityValid = true,
            IsSignatureValid = true,
            IsChainTrustWarning = true,
            IsNotRevoked = notRevoked,
            RevocationSource = source
        };

        result.IsValid.ShouldBeFalse();
    }
}
