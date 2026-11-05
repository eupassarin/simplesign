using System.Security.Cryptography;
using Shouldly;
using SimpleSign.Brasil.IcpBrasil;
using SimpleSign.TestHelpers;

namespace SimpleSign.Brasil.Tests;

[Trait("Category", "Unit")]
public sealed class IcpBrasilTimestampTests
{
    private static readonly byte[] s_data = "contrato"u8.ToArray();

    [Fact]
    public void Verify_NonIcpTsa_NotTrusted()
    {
        byte[] token = TimestampTestResponseBuilder.CreateTokenForData(s_data, HashAlgorithmName.SHA256);

        var result = IcpBrasilTimestamp.Verify(token, s_data);

        result.IsImprintValid.ShouldBeTrue();
        result.IsIntegrityValid.ShouldBeTrue();
        result.IsTsaTrusted.ShouldBe(false);
        result.IsValid.ShouldBeFalse();
    }

    [Fact]
    public void VerifyHash_NonIcpTsa_NotTrustedEvenInHomologation()
    {
        byte[] token = TimestampTestResponseBuilder.CreateTokenForData(s_data, HashAlgorithmName.SHA256);

        var result = IcpBrasilTimestamp.VerifyHash(token, SHA256.HashData(s_data), HashAlgorithmName.SHA256, IcpBrasilEnvironment.Homologation);

        result.IsImprintValid.ShouldBeTrue();
        result.IsTsaTrusted.ShouldBe(false);
    }
}
