using System.Text.Json;
using Shouldly;
using SimpleSign.Cli.Commands;
using SimpleSign.Cli.Json;
using SimpleSign.Core.Validation;

namespace SimpleSign.Cli.Tests;

public sealed class ValidationRevocationTests
{
    [Theory]
    [InlineData(RevocationSource.None, true, null, SignatureIndication.Valid, "not checked")]
    [InlineData(RevocationSource.Indeterminate, true, null, SignatureIndication.Indeterminate, "indeterminate")]
    [InlineData(RevocationSource.OnlineOcsp, true, false, SignatureIndication.Valid, "✓")]
    [InlineData(RevocationSource.EmbeddedCrl, false, true, SignatureIndication.Invalid, "✗")]
    public void MapValidation_RevocationStatus_PreservesUnknownAndUnchecked(
        RevocationSource source, bool notRevoked, bool? revoked, SignatureIndication indication, string text)
    {
        var result = new SignatureValidationResult
        {
            IsIntegrityValid = true,
            IsSignatureValid = true,
            IsCertificateChainValid = true,
            IsNotRevoked = notRevoked,
            RevocationSource = source
        };

        var output = JsonMapper.MapValidation("signed.pdf", [result]);
        output.Signatures[0].Revoked.ShouldBe(revoked);
        output.Signatures[0].Indication.ShouldBe(indication.ToString());
        ValidateCommand.FormatRevocationStatus(result).ShouldContain(text);
        using var json = JsonDocument.Parse(JsonSerializer.Serialize(output, CliJsonContext.Default.ValidateOutput));
        var signature = json.RootElement.GetProperty("signatures")[0];
        signature.TryGetProperty("valid", out _).ShouldBeFalse();
        var status = signature.GetProperty("revoked");
        if (revoked.HasValue)
        {
            status.GetBoolean().ShouldBe(revoked.Value);
        }
        else
        {
            status.ValueKind.ShouldBe(JsonValueKind.Null);
        }
    }

    [Fact]
    public void MapValidation_UntrustedChain_ExposesIndeterminateIndication()
    {
        var result = new SignatureValidationResult
        {
            IsIntegrityValid = true,
            IsSignatureValid = true,
            IsCertificateChainValid = false,
            IsNotRevoked = true
        };

        var output = JsonMapper.MapValidation("signed.pdf", [result]);

        output.Signatures[0].Indication.ShouldBe("Indeterminate");
    }
}
