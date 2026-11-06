using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace SimpleSign.Signers.Pkcs11.Tests;

/// <summary>
/// Creates a SoftHSM2 token with an RSA and an EC signing key (each with a certificate issued
/// by a test CA) plus the CA certificate. Active only when <c>SOFTHSM2_MODULE</c> points to
/// <c>libsofthsm2.so</c>, <c>SOFTHSM2_CONF</c> points to a writable SoftHSM2 configuration, and
/// <c>softhsm2-util</c> and <c>pkcs11-tool</c> (OpenSC) are on the PATH, as set up by
/// <c>scripts/tests/pkcs11-run.sh</c>.
/// </summary>
/// <remarks>
/// <c>SOFTHSM2_CONF</c> must be set before the test process starts: on Unix,
/// <see cref="Environment.SetEnvironmentVariable(string, string)"/> is not visible to
/// <c>getenv()</c> in native libraries. Each fixture creates a token with a unique label, so
/// test runs for several target frameworks can share one token directory.
/// </remarks>
public sealed class SoftHsmFixture : IDisposable
{
    internal const string UserPin = "1234";
    internal const string RsaKeyLabel = "rsa-signer";
    internal const string EcKeyLabel = "ec-signer";
    internal static readonly byte[] RsaKeyId = [0x01];
    internal static readonly byte[] EcKeyId = [0x02];

    private readonly string? _directory;

    public SoftHsmFixture()
    {
        string? module = Environment.GetEnvironmentVariable("SOFTHSM2_MODULE");
        if (string.IsNullOrEmpty(module) || !File.Exists(module))
        {
            SkipReason = "SOFTHSM2_MODULE is not set; run scripts/tests/pkcs11.sh to test with SoftHSM2 in Docker.";
            return;
        }

        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("SOFTHSM2_CONF")))
        {
            SkipReason = "SOFTHSM2_CONF is not set; run scripts/tests/pkcs11-run.sh, which prepares it.";
            return;
        }

        ModulePath = module;
        TokenLabel = $"ss-test-{Guid.NewGuid():N}"[..20];
        _directory = Directory.CreateTempSubdirectory("simplesign-softhsm-").FullName;

        Run("softhsm2-util", "--init-token", "--free", "--label", TokenLabel, "--so-pin", "0000", "--pin", UserPin);

        using RSA caKey = RSA.Create(2048);
        var caRequest = new CertificateRequest("CN=SoftHSM Test CA, O=SimpleSign Tests", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        X509Certificate2 ca = caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));
        CaCertificate = ca;

        using RSA rsaKey = RSA.Create(2048);
        RsaCertificate = Issue(ca, caKey, new CertificateRequest("CN=SoftHSM RSA Signer, C=BR", rsaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), [0x11]);
        Import(rsaKey.ExportPkcs8PrivateKey(), RsaCertificate, RsaKeyId, RsaKeyLabel);

        using ECDsa ecKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        EcCertificate = Issue(ca, caKey, new CertificateRequest("CN=SoftHSM EC Signer, C=BR", ecKey, HashAlgorithmName.SHA256), [0x12]);
        Import(ecKey.ExportPkcs8PrivateKey(), EcCertificate, EcKeyId, EcKeyLabel);

        WriteObject(CaCertificate.RawData, "cert", [0x03], "test-ca");
    }

    /// <summary>Why the token tests are skipped, or <see langword="null"/> when SoftHSM2 is available.</summary>
    public string? SkipReason { get; }

    public string ModulePath { get; } = string.Empty;

    public string TokenLabel { get; } = string.Empty;

    public X509Certificate2 CaCertificate { get; } = null!;

    public X509Certificate2 RsaCertificate { get; } = null!;

    public X509Certificate2 EcCertificate { get; } = null!;

    public Pkcs11SignerOptions Options(string? keyLabel = null, string pin = UserPin) => new()
    {
        LibraryPath = ModulePath,
        TokenLabel = TokenLabel,
        KeyLabel = keyLabel,
        Pin = pin,
    };

    public void Dispose()
    {
        CaCertificate?.Dispose();
        RsaCertificate?.Dispose();
        EcCertificate?.Dispose();
        if (_directory is not null)
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    private static X509Certificate2 Issue(X509Certificate2 ca, RSA caKey, CertificateRequest request, byte[] serial)
    {
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, false));
        return request.Create(
            ca.SubjectName,
            X509SignatureGenerator.CreateForRSA(caKey, RSASignaturePadding.Pkcs1),
            DateTimeOffset.UtcNow.AddHours(-1),
            DateTimeOffset.UtcNow.AddYears(1),
            serial);
    }

    private void Import(byte[] pkcs8, X509Certificate2 certificate, byte[] id, string label)
    {
        WriteObject(pkcs8, "privkey", id, label);
        WriteObject(certificate.RawData, "cert", id, label);
    }

    private void WriteObject(byte[] der, string type, byte[] id, string label)
    {
        string file = Path.Combine(_directory!, $"{label}-{type}.der");
        File.WriteAllBytes(file, der);
        try
        {
            Run("pkcs11-tool", "--module", ModulePath, "--token-label", TokenLabel, "--login", "--pin", UserPin,
                "--write-object", file, "--type", type, "--id", Convert.ToHexString(id), "--label", label);
        }
        finally
        {
            File.Delete(file);
        }
    }

    private static void Run(string fileName, params string[] arguments)
    {
        var start = new ProcessStartInfo(fileName)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (string argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start)!;
        string output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"{fileName} failed ({process.ExitCode}): {output}");
        }
    }
}

[CollectionDefinition(Name)]
public sealed class SoftHsmCollection : ICollectionFixture<SoftHsmFixture>
{
    public const string Name = "SoftHSM";
}
