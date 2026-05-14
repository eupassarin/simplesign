using static SimpleSign.Brasil.Signing.AuthenticationMethodExtensions;
using BrasilAdvanced = SimpleSign.Brasil.Signing.AdvancedSignatureInfo;
using BrasilAuth = SimpleSign.Brasil.Signing.AuthenticationMethod;

namespace SimpleSign.Brasil.Tests;

public class AdvancedSignatureInfoTests
{
    [Theory]
    [InlineData("12345678901", "***.456.789-**")]
    [InlineData("00000000000", "***.000.000-**")]
    [InlineData("123.456.789-01", "***.456.789-**")]
    public void MaskCpf_MasksCorrectly(string input, string expected)
    {
        Assert.Equal(expected, BrasilAdvanced.MaskCpf(input));
    }

    [Theory]
    [InlineData("")]
    [InlineData("1234")]
    [InlineData("123456789012")] // 12 digits
    public void MaskCpf_ThrowsForInvalidInput(string input)
    {
        Assert.ThrowsAny<ArgumentException>(() => BrasilAdvanced.MaskCpf(input));
    }

    [Fact]
    public void AuthenticationMethod_ToDisplayString_ReturnsEnglish()
    {
        Assert.Equal("Institutional login", BrasilAuth.InstitutionalLogin.ToDisplayString());
        Assert.Equal("Digital certificate", BrasilAuth.DigitalCertificate.ToDisplayString());
        Assert.Equal("Gov.br", BrasilAuth.GovBr.ToDisplayString());
        Assert.Equal("Facial biometrics", BrasilAuth.FacialBiometrics.ToDisplayString());
        Assert.Equal("Token OTP", BrasilAuth.TokenOtp.ToDisplayString());
        Assert.Equal("Username and password", BrasilAuth.UsernamePassword.ToDisplayString());
    }
}
