using System.Text.Json;
using Shouldly;
using SimpleSign.Cli.Commands;
using SimpleSign.Cli.Json;
using SimpleSign.Core.Validation;

namespace SimpleSign.Cli.Tests;

public sealed class ValidationRevocationTests
{
    [Theory]
    [InlineData(RevocationSource.None, true, null, true, "not checked")]
    [InlineData(RevocationSource.Indeterminate, true, null, false, "indeterminate")]
    [InlineData(RevocationSource.OnlineOcsp, true, false, true, "✓")]
    [InlineData(RevocationSource.EmbeddedCrl, false, true, false, "✗")]
    public void MapValidation_RevocationStatus_PreservesUnknownAndUnchecked(
        RevocationSource source, bool notRevoked, bool? revoked, bool valid, string text)
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
        output.Signatures[0].Valid.ShouldBe(valid);
        ValidateCommand.FormatRevocationStatus(result).ShouldContain(text);
        using var json = JsonDocument.Parse(JsonSerializer.Serialize(output, CliJsonContext.Default.ValidateOutput));
        var status = json.RootElement.GetProperty("signatures")[0].GetProperty("revoked");
        if (revoked.HasValue)
        {
            status.GetBoolean().ShouldBe(revoked.Value);
        }
        else
        {
            status.ValueKind.ShouldBe(JsonValueKind.Null);
        }
    }
}
