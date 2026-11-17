using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Signers.Pkcs11;

namespace SimpleSign.Peru.Iofe.Accredited.Tests;

/// <summary>
/// A SoftHSM2 token with three signing keys under <see cref="IofeTestPki"/>: <see cref="AgentKey"/> (digitalSignature
/// and nonRepudiation, not extractable), <see cref="DigitalSignatureOnlyKey"/> (no nonRepudiation, not extractable) and
/// <see cref="ExtractableKey"/> (imported as extractable), plus the intermediate CA certificate. Active only when
/// <c>SOFTHSM2_MODULE</c> and <c>SOFTHSM2_CONF</c> are set and <c>softhsm2-util</c> and <c>pkcs11-tool</c> are on the
/// PATH, as <c>scripts/tests/pkcs11-run.sh</c> sets them up.
/// </summary>
public sealed class IofeTokenFixture : IDisposable
{
    internal const string UserPin = "1234";
    internal const string AgentKey = "agent";
    internal const string DigitalSignatureOnlyKey = "ds-only";
    internal const string ExtractableKey = "extractable";

    // What SoftHSM2 reports in CK_TOKEN_INFO.
    internal const string Manufacturer = "SoftHSM project";
    internal const string Model = "SoftHSM v2";

    private readonly string? _directory;
    private readonly X509Certificate2? _digitalSignatureOnly;
    private readonly X509Certificate2? _extractable;

    public IofeTokenFixture()
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
        TokenLabel = $"iofe-{Guid.NewGuid():N}"[..20];
        _directory = Directory.CreateTempSubdirectory("simplesign-iofe-softhsm-").FullName;
        TestPki = new IofeTestPki();

        Run("softhsm2-util", "--init-token", "--free", "--label", TokenLabel, "--so-pin", "0000", "--pin", UserPin);

        using (var agentKey = RSA.Create())
        {
            agentKey.ImportFromPem(TestPki.Pki.LeafPrivateKeyPem());
            Import(agentKey.ExportPkcs8PrivateKey(), TestPki.Pki.Leaf, [0x01], AgentKey, extractable: false);
        }

        using (var key = RSA.Create(2048))
        {
            _digitalSignatureOnly = TestPki.IssueSigner("CN=IOFE Test Digital Signature Only, O=SimpleSign Tests", key, X509KeyUsageFlags.DigitalSignature);
            Import(key.ExportPkcs8PrivateKey(), _digitalSignatureOnly, [0x02], DigitalSignatureOnlyKey, extractable: false);
        }

        using (var key = RSA.Create(2048))
        {
            _extractable = TestPki.IssueSigner(
                "CN=IOFE Test Extractable Key, O=SimpleSign Tests", key, X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation);
            Import(key.ExportPkcs8PrivateKey(), _extractable, [0x03], ExtractableKey, extractable: true);
        }

        WriteObject(TestPki.Pki.IntermediateCa.RawData, "cert", [0x10], "intermediate-ca", extractable: false);
    }

    /// <summary>Why the token tests are skipped, or <see langword="null"/> when SoftHSM2 is available.</summary>
    public string? SkipReason { get; }

    internal string ModulePath { get; } = string.Empty;

    internal string TokenLabel { get; } = string.Empty;

    internal IofeTestPki TestPki { get; } = null!;

    internal Pkcs11SignerOptions Module(string keyLabel) => new()
    {
        LibraryPath = ModulePath,
        TokenLabel = TokenLabel,
        KeyLabel = keyLabel,
        Pin = UserPin,
    };

    internal static IofeModuleDeclaration Declaration { get; } = new(Manufacturer, Model, "ninguna (token de software para pruebas)", "n/a");

    public void Dispose()
    {
        _digitalSignatureOnly?.Dispose();
        _extractable?.Dispose();
        TestPki?.Dispose();
        if (_directory is not null)
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    private void Import(byte[] pkcs8, X509Certificate2 certificate, byte[] id, string label, bool extractable)
    {
        WriteObject(pkcs8, "privkey", id, label, extractable);
        WriteObject(certificate.RawData, "cert", id, label, extractable: false);
    }

    private void WriteObject(byte[] der, string type, byte[] id, string label, bool extractable)
    {
        string file = Path.Combine(_directory!, $"{label}-{type}.der");
        File.WriteAllBytes(file, der);
        try
        {
            List<string> arguments =
            [
                "--module", ModulePath, "--token-label", TokenLabel, "--login", "--pin", UserPin,
                "--write-object", file, "--type", type, "--id", Convert.ToHexString(id), "--label", label,
            ];
            if (extractable)
            {
                arguments.Add("--extractable");
            }

            Run("pkcs11-tool", [.. arguments]);
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
public sealed class IofeTokenCollection : ICollectionFixture<IofeTokenFixture>
{
    public const string Name = "IOFE SoftHSM";
}
