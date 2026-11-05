using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.CAdES.Tests;

/// <summary>Co-signatures, countersignatures, attached content and hash-only validation.</summary>
public sealed class CadesMultiSignerTests : IDisposable
{
    private readonly X509Certificate2 _alice = TestCertificateFactory.CreateSelfSignedCert("CN=Alice, O=Tests");
    private readonly X509Certificate2 _bob = TestCertificateFactory.CreateSelfSignedCert("CN=Bob, O=Tests");
    private readonly X509Certificate2 _carol = TestCertificateFactory.CreateSelfSignedCert("CN=Carol, O=Tests");
    private readonly byte[] _data = "contrato de prestação de serviços"u8.ToArray();

    public void Dispose()
    {
        _alice.Dispose();
        _bob.Dispose();
        _carol.Dispose();
    }

    private CadesSignatureValidator Validator() =>
        new(new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false, TrustedRoots = [_alice, _bob, _carol] });

    [Fact]
    public async Task CoSign_Detached_AllSignersValidate()
    {
        byte[] one = await CadesSigner.Document(_data).WithCertificate(_alice).SignAsync();
        byte[] two = await CadesSigner.CoSign(one, _data).WithCertificate(_bob).SignAsync();
        byte[] three = await CadesSigner.CoSign(two, _data).WithCertificate(_carol).SignAsync();

        var report = Validator().ValidateAll(three, _data);

        Assert.True(report.IsValid, string.Join("; ", report.Signers.SelectMany(s => s.Result.Errors)));
        Assert.Equal(["CN=Alice, O=Tests", "CN=Bob, O=Tests", "CN=Carol, O=Tests"],
            report.Signers.Select(s => s.Result.SignerCertificate!.Subject));
        Assert.Equal(3, CmsParser.ParseAll(three).Signers.Count);
    }

    [Fact]
    public async Task CoSign_FirstSignerStillValidatesWithValidate()
    {
        byte[] one = await CadesSigner.Document(_data).WithCertificate(_alice).SignAsync();
        byte[] two = await CadesSigner.CoSign(one, _data).WithCertificate(_bob).SignAsync();

        var first = Validator().Validate(two, _data);

        Assert.True(first.IsSignatureValid && first.IsIntegrityValid, string.Join("; ", first.Errors));
        Assert.Equal("CN=Alice, O=Tests", first.SignerCertificate!.Subject);
    }

    [Fact]
    public async Task CoSign_DataNotCoveredByExistingSignature_Throws()
    {
        byte[] one = await CadesSigner.Document(_data).WithCertificate(_alice).SignAsync();

        Assert.Throws<ArgumentException>(() => CadesSigner.CoSign(one, "outro documento"u8.ToArray()));
        Assert.Throws<ArgumentException>(() => CadesSigner.CoSign(one));
    }

    [Fact]
    public async Task CoSign_Attached_KeepsContentAndValidatesWithoutData()
    {
        byte[] p7m = await CadesSigner.Document(_data).WithCertificate(_alice).WithContentType(CadesContentType.Enveloped).SignAsync();
        byte[] cosigned = await CadesSigner.CoSign(p7m).WithCertificate(_bob).SignAsync();

        var report = Validator().ValidateAll(cosigned);

        Assert.True(report.IsValid, string.Join("; ", report.Signers.SelectMany(s => s.Result.Errors)));
        Assert.Equal(2, report.Signers.Count);
        Assert.Equal(_data, CadesSigner.ExtractContent(cosigned));
    }

    [Fact]
    public async Task ValidateAll_TamperedSigner_InvalidatesOnlyThatSigner()
    {
        byte[] one = await CadesSigner.Document(_data).WithCertificate(_alice).SignAsync();
        // A signer over other content, merged in directly: it does not cover the document.
        byte[] other = await CadesSigner.Document("adulterado"u8.ToArray()).WithCertificate(_bob).SignAsync();
        byte[] mixed = CmsComposer.AddSigner(one, other);

        var report = Validator().ValidateAll(mixed, _data);

        Assert.False(report.IsValid);
        Assert.True(report.Signers[0].IsValid);
        Assert.False(report.Signers[1].IsValid);
        Assert.False(report.Signers[1].Result.IsIntegrityValid);
    }

    [Fact]
    public async Task CounterSign_ValidatesAgainstParentSignature_WithoutContentType()
    {
        byte[] one = await CadesSigner.Document(_data).WithCertificate(_alice).SignAsync();
        byte[] two = await CadesSigner.CoSign(one, _data).WithCertificate(_bob).SignAsync();
        byte[] countersigned = await CadesSigner.CounterSign(two, signerIndex: 1).WithCertificate(_carol).SignAsync();

        var set = CmsParser.ParseAll(countersigned);
        var report = Validator().ValidateAll(countersigned, _data);

        Assert.True(report.IsValid, string.Join("; ", report.Signers.SelectMany(s => s.CounterSignatures).SelectMany(c => c.Result.Errors)));
        Assert.Empty(report.Signers[0].CounterSignatures);
        var counter = Assert.Single(report.Signers[1].CounterSignatures);
        Assert.Equal("CN=Carol, O=Tests", counter.Result.SignerCertificate!.Subject);
        Assert.Null(set.Signers[1].CounterSignatures[0].ContentTypeOid);
        Assert.Equal(
            CadesSigner.HashFor(Oids.Sha256, set.Signers[1].Signature!),
            set.Signers[1].CounterSignatures[0].MessageDigest);
    }

    [Fact]
    public async Task CounterSign_Twice_AccumulatesCounterSignatures()
    {
        byte[] one = await CadesSigner.Document(_data).WithCertificate(_alice).SignAsync();
        byte[] c1 = await CadesSigner.CounterSign(one).WithCertificate(_bob).SignAsync();
        byte[] c2 = await CadesSigner.CounterSign(c1).WithCertificate(_carol).SignAsync();

        var report = Validator().ValidateAll(c2, _data);

        Assert.True(report.IsValid);
        Assert.Equal(2, report.Signers[0].CounterSignatures.Count);
    }

    [Fact]
    public async Task CounterSign_NoSuchSigner_Throws()
    {
        byte[] one = await CadesSigner.Document(_data).WithCertificate(_alice).SignAsync();

        Assert.Throws<ArgumentOutOfRangeException>(() => CadesSigner.CounterSign(one, signerIndex: 1));
    }

    [Fact]
    public async Task Validate_AttachedWithoutData_UsesEncapsulatedContent()
    {
        byte[] p7m = await CadesSigner.Document(_data).WithCertificate(_alice).WithContentType(CadesContentType.Enveloped).SignAsync();

        var result = Validator().Validate(p7m, null);

        Assert.True(result.IsIntegrityValid && result.IsSignatureValid, string.Join("; ", result.Errors));
    }

    [Fact]
    public async Task Validate_DetachedWithoutData_ReportsError()
    {
        byte[] p7s = await CadesSigner.Document(_data).WithCertificate(_alice).SignAsync();

        var result = Validator().Validate(p7s, null);

        Assert.False(result.IsIntegrityValid);
        Assert.Contains(result.Errors, e => e.Contains("detached", StringComparison.Ordinal));
        Assert.Throws<ArgumentException>(() => CadesSigner.ExtractContent(p7s));
    }

    [Fact]
    public async Task ValidateWithHash_MatchesWithoutTheDocument()
    {
        byte[] p7s = await CadesSigner.Document(_data).WithCertificate(_alice).SignAsync();

        var right = Validator().ValidateWithHash(p7s, SHA256.HashData(_data), Oids.Sha256);
        var wrong = Validator().ValidateWithHash(p7s, SHA256.HashData("x"u8), Oids.Sha256);
        var otherAlgorithm = Validator().ValidateWithHash(p7s, SHA512.HashData(_data), Oids.Sha512);

        Assert.True(right.IsIntegrityValid && right.IsSignatureValid, string.Join("; ", right.Errors));
        Assert.False(wrong.IsIntegrityValid);
        Assert.False(otherAlgorithm.IsIntegrityValid);
    }

    [Fact]
    public async Task OpenSsl_VerifiesCoSignedAndCounterSignedCms()
    {
        string? openssl = FindOpenSsl();
        if (openssl is null)
        {
            return; // OpenSSL not installed: interop not checked on this machine.
        }

        byte[] one = await CadesSigner.Document(_data).WithCertificate(_alice).SignAsync();
        byte[] two = await CadesSigner.CoSign(one, _data).WithCertificate(_bob).SignAsync();
        byte[] signed = await CadesSigner.CounterSign(two, 1).WithCertificate(_carol).SignAsync();
        string dir = Path.Combine(Path.GetTempPath(), "simplesign-cms-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllBytes(Path.Combine(dir, "sig.p7s"), signed);
            File.WriteAllBytes(Path.Combine(dir, "data.bin"), _data);
            var psi = new System.Diagnostics.ProcessStartInfo(openssl,
                ["cms", "-verify", "-inform", "DER", "-binary", "-noverify",
                 "-in", Path.Combine(dir, "sig.p7s"), "-content", Path.Combine(dir, "data.bin"), "-out", Path.Combine(dir, "out.bin")])
            {
                RedirectStandardError = true,
                RedirectStandardOutput = true,
            };
            using var process = System.Diagnostics.Process.Start(psi)!;
            string stderr = await process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();

            Assert.True(process.ExitCode == 0, stderr);
            Assert.Contains("Verification successful", stderr, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    private static string? FindOpenSsl() =>
        (Environment.GetEnvironmentVariable("PATH") ?? string.Empty)
            .Split(Path.PathSeparator)
            .Select(d => Path.Combine(d, OperatingSystem.IsWindows() ? "openssl.exe" : "openssl"))
            .FirstOrDefault(File.Exists);
}
