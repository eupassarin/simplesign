using Shouldly;
using SimpleSign.Brazil.Signing;
using SimpleSign.Cli.Rendering;
using SimpleSign.Core.Signing;

namespace SimpleSign.Cli.Tests;

[Trait("Category", "Unit")]
public sealed class BrasilSignOptionsTests
{
    [Fact]
    public void Build_WithRequiredFields_ReturnsInfo()
    {
        var result = BrasilSignOptions.Build("André Almeida", "12345678901", null,
            null, null, null, null, null, null);

        result.ShouldNotBeNull();
        result.SignerName.ShouldBe("André Almeida");
        result.Cpf.ShouldBe("12345678901");
        result.AuthMethod.ShouldBe(AuthenticationMethod.DigitalCertificate);
        result.CommitmentType.ShouldBe(CommitmentType.ProofOfApproval);
        result.Email.ShouldBeNull();
        result.InstitutionName.ShouldBeNull();
        result.InstitutionCnpj.ShouldBeNull();
        result.PolicyOid.ShouldBeNull();
        result.PolicyUri.ShouldBeNull();
    }

    [Fact]
    public void Build_WithAllFields_ReturnsInfo()
    {
        var result = BrasilSignOptions.Build("André Almeida", "12345678901", "gov-br",
            "andre@example.com", "TCE-ES", "12345678000199",
            "origin", "1.2.3.4", "https://policy.example.com");

        result.SignerName.ShouldBe("André Almeida");
        result.Cpf.ShouldBe("12345678901");
        result.AuthMethod.ShouldBe(AuthenticationMethod.GovBr);
        result.Email.ShouldBe("andre@example.com");
        result.InstitutionName.ShouldBe("TCE-ES");
        result.InstitutionCnpj.ShouldBe("12345678000199");
        result.CommitmentType.ShouldBe(CommitmentType.ProofOfOrigin);
        result.PolicyOid.ShouldBe("1.2.3.4");
        result.PolicyUri.ShouldBe("https://policy.example.com");
    }

    [Theory]
    [InlineData("digital-certificate", AuthenticationMethod.DigitalCertificate)]
    [InlineData("digital_certificate", AuthenticationMethod.DigitalCertificate)]
    [InlineData("gov-br", AuthenticationMethod.GovBr)]
    [InlineData("gov_br", AuthenticationMethod.GovBr)]
    [InlineData("govbr", AuthenticationMethod.GovBr)]
    [InlineData("institutional-login", AuthenticationMethod.InstitutionalLogin)]
    [InlineData("institutional_login", AuthenticationMethod.InstitutionalLogin)]
    [InlineData("facial-biometrics", AuthenticationMethod.FacialBiometrics)]
    [InlineData("facial_biometrics", AuthenticationMethod.FacialBiometrics)]
    [InlineData("token-otp", AuthenticationMethod.TokenOtp)]
    [InlineData("token_otp", AuthenticationMethod.TokenOtp)]
    [InlineData("username-password", AuthenticationMethod.UsernamePassword)]
    [InlineData("username_password", AuthenticationMethod.UsernamePassword)]
    [InlineData(null, AuthenticationMethod.DigitalCertificate)]
    [InlineData("unknown", AuthenticationMethod.DigitalCertificate)]
    public void ParseAuthMethod_ReturnsExpected(string? input, AuthenticationMethod expected) =>
        BrasilSignOptions.ParseAuthMethod(input).ShouldBe(expected);

    [Theory]
    [InlineData("approval", CommitmentType.ProofOfApproval)]
    [InlineData("origin", CommitmentType.ProofOfOrigin)]
    [InlineData(null, CommitmentType.ProofOfApproval)]
    [InlineData("unknown", CommitmentType.ProofOfApproval)]
    public void ParseCommitmentType_ReturnsExpected(string? input, CommitmentType expected) =>
        BrasilSignOptions.ParseCommitmentType(input).ShouldBe(expected);
}
