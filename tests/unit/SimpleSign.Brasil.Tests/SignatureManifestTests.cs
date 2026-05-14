using SimpleSign.Core.Signing;
using BrasilAdvanced = SimpleSign.Brasil.Signing.AdvancedSignatureInfo;
using BrasilAuth = SimpleSign.Brasil.Signing.AuthenticationMethod;
using BrasilManifest = SimpleSign.Brasil.Signing.SignatureManifest;

namespace SimpleSign.Brasil.Tests;

public class SignatureManifestTests
{
    [Fact]
    public void FromInfo_CreatesValidManifest()
    {
        var info = new BrasilAdvanced
        {
            SignerName = "André Almeida",
            Cpf = "12345678901",
            AuthMethod = BrasilAuth.InstitutionalLogin,
            Email = "andre@tce.es.gov.br",
            IpAddress = "192.168.1.100",
            InstitutionName = "TCE-ES",
            InstitutionCnpj = "12345678000199",
            CommitmentType = CommitmentType.ProofOfApproval,
        };

        var manifest = BrasilManifest.FromInfo(info);

        Assert.Equal("aea", manifest.Type);
        Assert.Equal("Lei 14.063/2020", manifest.Law);
        Assert.Equal("André Almeida", manifest.Signer.Name);
        Assert.Equal("***.456.789-**", manifest.Signer.Cpf);
        Assert.Equal("andre@tce.es.gov.br", manifest.Signer.Email);
        Assert.Equal("192.168.1.100", manifest.Evidence.Ip);
        Assert.Equal("Institutional login", manifest.Evidence.AuthMethod);
        Assert.NotNull(manifest.Institution);
        Assert.Equal("TCE-ES", manifest.Institution!.Name);
        Assert.Equal("12345678000199", manifest.Institution.Cnpj);
        Assert.Equal("proofOfApproval", manifest.Commitment);
    }

    [Fact]
    public void RoundTrip_JsonSerialization()
    {
        var info = new BrasilAdvanced
        {
            SignerName = "Test User",
            Cpf = "98765432100",
            AuthMethod = BrasilAuth.GovBr,
            Email = "test@gov.br",
        };

        var manifest = BrasilManifest.FromInfo(info);
        var json = manifest.ToJsonUtf8();
        var parsed = BrasilManifest.FromJsonUtf8(json);

        Assert.NotNull(parsed);
        Assert.Equal(manifest.Signer.Name, parsed!.Signer.Name);
        Assert.Equal(manifest.Signer.Cpf, parsed.Signer.Cpf);
        Assert.Equal(manifest.Evidence.AuthMethod, parsed.Evidence.AuthMethod);
    }
}
