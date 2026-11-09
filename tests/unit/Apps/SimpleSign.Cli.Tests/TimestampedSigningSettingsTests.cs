using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.Cli.Commands;
using SimpleSign.TestHelpers;

namespace SimpleSign.Cli.Tests;

[Trait("Category", "Unit")]
public sealed class TimestampedSigningSettingsTests
{
    private const string Tsa = "https://tsa.example.com/tsr";

    [Fact]
    public void Timestamp_UserAndPassword_SendsBasicAuthorization()
    {
        var settings = new XadesSignCommand.Settings { TsaUser = "alice", TsaPassword = "secret" };

        var options = settings.Timestamp(Tsa);

        options.Endpoint.ShouldBe(new Uri(Tsa));
        options.Authorization!.Scheme.ShouldBe("Basic");
        Encoding.UTF8.GetString(Convert.FromBase64String(options.Authorization.Parameter!)).ShouldBe("alice:secret");
    }

    [Fact]
    public void Timestamp_TokenFromEnvironment_SendsBearer()
    {
        Environment.SetEnvironmentVariable("SIMPLESIGN_TEST_TSA_TOKEN", "t0ken");
        try
        {
            var settings = new XadesSignCommand.Settings { TsaToken = "env:SIMPLESIGN_TEST_TSA_TOKEN" };

            var options = settings.Timestamp(Tsa);

            options.Authorization!.Scheme.ShouldBe("Bearer");
            options.Authorization.Parameter.ShouldBe("t0ken");
        }
        finally
        {
            Environment.SetEnvironmentVariable("SIMPLESIGN_TEST_TSA_TOKEN", null);
        }
    }

    [Fact]
    public void ArchiveTimestamp_ClientCertificate_IsLoadedForBothTsas()
    {
        string path = Path.Combine(Path.GetTempPath(), $"tsa-client-{Guid.NewGuid():N}.pfx");
        using (var cert = TestCertificateFactory.CreateSelfSignedCert())
        {
            File.WriteAllBytes(path, cert.Export(X509ContentType.Pfx, "pw"));
        }

        try
        {
            var settings = new XadesSignCommand.Settings { TsaCertificate = path, TsaCertificatePassword = "pw" };

            var signature = settings.Timestamp(Tsa);
            var archive = settings.ArchiveTimestamp("https://archive.example.com/tsr");

            signature.ClientCertificate.ShouldNotBeNull();
            archive.ClientCertificate.ShouldNotBeNull();
            archive.Authorization.ShouldBeNull();
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Timestamp_NoCredentials_HasNone()
    {
        var options = new XadesSignCommand.Settings().Timestamp(Tsa);

        options.Authorization.ShouldBeNull();
        options.ClientCertificate.ShouldBeNull();
    }

    [Theory]
    [InlineData(null, "alice", "secret", null, "require --tsa")]
    [InlineData(Tsa, "alice", null, null, "go together")]
    [InlineData(Tsa, "alice", "secret", "token", "mutually exclusive")]
    public void ValidateTsaCredentials_Inconsistent_IsAnError(string? tsa, string? user, string? password, string? token, string expected) =>
        new XadesSignCommand.Settings { TsaUser = user, TsaPassword = password, TsaToken = token }
            .ValidateTsaCredentials(tsa).ShouldNotBeNull().ShouldContain(expected);

    [Fact]
    public void ValidateTsaCredentials_CertificatePasswordAlone_IsAnError() =>
        new XadesSignCommand.Settings { TsaCertificatePassword = "pw" }
            .ValidateTsaCredentials(Tsa).ShouldNotBeNull().ShouldContain("requires --tsa-cert");

    [Fact]
    public void ValidateTsaCredentials_MissingCertificateFile_IsAnError() =>
        new XadesSignCommand.Settings { TsaCertificate = "/nonexistent/tsa.pfx" }
            .ValidateTsaCredentials(Tsa).ShouldNotBeNull().ShouldContain("not found");

    [Fact]
    public void ValidateTsaCredentials_None_IsValid() =>
        new XadesSignCommand.Settings().ValidateTsaCredentials(null).ShouldBeNull();
}
