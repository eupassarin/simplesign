using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.CAdES.Tests;

/// <summary>Co-signatures, countersignatures, attached content and hash-only validation.</summary>
[Trait("Category", "Unit")]
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
    public async Task CounterSign_IsEvaluatedInTheCounterSignatureContext()
    {
        byte[] one = await CadesSigner.Document(_data).WithCertificate(_alice).SignAsync();
        byte[] countersigned = await CadesSigner.CounterSign(one).WithCertificate(_carol).SignAsync();

        var report = Validator().ValidateAll(countersigned, _data);

        var counter = Assert.Single(report.Signers[0].CounterSignatures);
        Assert.Contains(counter.Result.Constraints, c => c.Id == "CounterSignatureConstraints/BasicSignatureConstraints/SignatureIntact" && c.Status == ConstraintStatus.Passed);
        Assert.DoesNotContain(counter.Result.Constraints, c => c.Id.StartsWith("SignatureConstraints/", StringComparison.Ordinal));
        Assert.DoesNotContain(report.Signers[0].Result.Constraints, c => c.Id.StartsWith("CounterSignatureConstraints/", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Validate_TrustedListsInTheOptions_AreEvaluated()
    {
        byte[] one = await CadesSigner.Document(_data).WithCertificate(_alice).SignAsync();
        var list = new SimpleSign.Core.Extensions.TrustedListInfo(
            "BR", null, "5", DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30), DateTimeOffset.UtcNow, IsWellSigned: true, [_alice]);
        var validator = new CadesSignatureValidator(new ValidationOptions
        {
            CheckRevocation = false,
            TrustSystemRoots = false,
            TrustedRoots = [_alice],
            TrustedLists = [list],
        });

        var report = validator.ValidateAll(one, _data);

        Assert.Contains(report.Signers[0].Result.Constraints, c => c.Id == "TrustedLists/TLWellSigned" && c.Status == ConstraintStatus.Passed);
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

    [Fact]
    public async Task CoSign_ArchiveOverArchive_EachSignerInfoKeepsAValidArchiveTimestampV3()
    {
        using var pki = new OfflinePki();
        byte[] rsa = await CadesSigner.Document(_data).WithCertificate(pki.Pki.Leaf, pki.Chain)
            .WithContentType(CadesContentType.Enveloped).WithHttpClientProvider(pki.Http).WithLevel(pki.Level("LTA")).SignAsync();
        byte[] rsaSignerInfo = SignerInfos(rsa)[0];

        byte[] cosigned = await CadesSigner.CoSign(rsa).WithCertificate(pki.Ecdsa, pki.Chain)
            .WithHttpClientProvider(pki.Http).WithLevel(pki.Level("LTA")).SignAsync();

        List<byte[]> signerInfos = SignerInfos(cosigned);
        Assert.Equal(2, signerInfos.Count);
        Assert.Equal(rsaSignerInfo, signerInfos[0]);
        foreach (byte[] signerInfo in signerInfos)
        {
            // ETSI EN 319 122-1 §5.5.3: the ATS-hash-index-v3 lists, for every value of every unsigned attribute of the
            // SignerInfo the archive-time-stamp-v3 is about, the digest of attrType || attrValue.
            HashSet<string> own = UnsignedAttributeValueDigests(signerInfo);
            Assert.All(IndexedUnsignedAttributeDigests(signerInfo), digest => Assert.Contains(digest, own));
        }

        var report = new CadesSignatureValidator(new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false })
            .ValidateAll(cosigned, trustAnchors: [pki.Pki.RootCa]);
        Assert.Equal(2, report.Signers.Count);
        Assert.All(report.Signers, signer =>
            Assert.True(signer.Result.HasValidArchiveTimestamp == true, string.Join("; ", signer.Result.Warnings)));
    }

    [Fact]
    public async Task CoSign_CoSignerWithArchiveTimestampV2_IsNotCheckedAsAV3()
    {
        using var pki = new OfflinePki();
        byte[] first = await CadesSigner.Document(_data).WithCertificate(pki.Pki.Leaf, pki.Chain)
            .WithContentType(CadesContentType.Enveloped).WithHttpClientProvider(pki.Http).WithLevel(pki.Level("T")).SignAsync();

        byte[] cosigned = await CadesSigner.CoSign(first).WithCertificate(pki.Ecdsa, pki.Chain)
            .WithHttpClientProvider(pki.Http).WithLevel(pki.Level("T")).WithExtendedValidationData(CadesExtendedForm.Archive).SignAsync();

        var report = new CadesSignatureValidator(new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false })
            .ValidateAll(cosigned, trustAnchors: [pki.Pki.RootCa]);
        var coSigner = report.Signers[1].Result;
        Assert.True(coSigner.IsValid, string.Join("; ", coSigner.Errors));
        Assert.Null(coSigner.HasValidArchiveTimestamp);
    }

    [Theory]
    [InlineData(AdesBaselineLevel.Timestamped)]
    [InlineData(AdesBaselineLevel.Archive)]
    public async Task Augment_CoSigned_RaisesTheFirstSignerAndKeepsTheCoSigner(AdesBaselineLevel target)
    {
        using var pki = new OfflinePki();
        byte[] cosigned = await CoSignedBasic(pki);
        List<byte[]> before = SignerInfos(cosigned);

        var result = await CadesAugmenter.Signature(cosigned, _data).WithTimestamp(pki.Timestamp)
            .WithHttpClientProvider(pki.Http).ToLevel(target).AugmentAsync();

        List<byte[]> after = SignerInfos(result.Signature);
        Assert.Equal(2, after.Count);
        Assert.NotEqual(before[0], after[0]);
        Assert.Equal(before[1], after[1]);
        Assert.Equal(target, result.Level);
        Assert.Equal(target, CadesAugmenter.LevelOf(result.Signature, 0));
        Assert.Equal(AdesBaselineLevel.Basic, CadesAugmenter.LevelOf(result.Signature, 1));
        var report = OfflineValidator().ValidateAll(result.Signature, _data, [pki.Pki.RootCa]);
        Assert.True(report.IsValid, string.Join("; ", report.Signers.SelectMany(s => s.Result.Errors)));
        Assert.True(report.Signers[0].Result.HasValidTimestamp);
        Assert.Null(report.Signers[1].Result.HasValidTimestamp);
        if (target == AdesBaselineLevel.Archive)
        {
            Assert.True(report.Signers[0].Result.HasValidArchiveTimestamp == true, string.Join("; ", report.Signers[0].Result.Warnings));
        }
    }

    [Fact]
    public async Task Augment_ForSecondSigner_RaisesItAndKeepsTheFirstByteIdentical()
    {
        using var pki = new OfflinePki();
        byte[] cosigned = await CoSignedBasic(pki);
        List<byte[]> before = SignerInfos(cosigned);

        var result = await CadesAugmenter.Signature(cosigned, _data).ForSigner(1).WithTimestamp(pki.Timestamp)
            .WithHttpClientProvider(pki.Http).ToLevel(AdesBaselineLevel.Archive).AugmentAsync();

        List<byte[]> after = SignerInfos(result.Signature);
        Assert.Equal(2, after.Count);
        Assert.Equal(before[0], after[0]);
        Assert.NotEqual(before[1], after[1]);
        Assert.Equal(AdesBaselineLevel.Basic, result.InitialLevel);
        Assert.Equal(AdesBaselineLevel.Archive, result.Level);
        Assert.Equal(AdesBaselineLevel.Basic, CadesAugmenter.LevelOf(result.Signature));
        var report = OfflineValidator().ValidateAll(result.Signature, _data, [pki.Pki.RootCa]);
        Assert.True(report.IsValid, string.Join("; ", report.Signers.SelectMany(s => s.Result.Errors)));
        Assert.Equal(pki.Ecdsa.Thumbprint, report.Signers[1].Result.SignerCertificate!.Thumbprint);
        Assert.True(report.Signers[1].Result.HasValidArchiveTimestamp == true, string.Join("; ", report.Signers[1].Result.Warnings));
    }

    [Fact]
    public async Task Augment_EachSignerInTurn_EveryArchiveTimestampV3Validates()
    {
        using var pki = new OfflinePki();
        byte[] cms = await CoSignedBasic(pki);

        for (int signer = 0; signer < 2; signer++)
        {
            cms = (await CadesAugmenter.Signature(cms, _data).ForSigner(signer).WithTimestamp(pki.Timestamp)
                .WithHttpClientProvider(pki.Http).ToLevel(AdesBaselineLevel.Archive).AugmentAsync()).Signature;
        }

        var report = OfflineValidator().ValidateAll(cms, _data, [pki.Pki.RootCa]);
        Assert.True(report.IsValid, string.Join("; ", report.Signers.SelectMany(s => s.Result.Errors)));
        Assert.Equal(2, report.Signers.Count);
        Assert.All(report.Signers, s => Assert.True(s.Result.HasValidArchiveTimestamp == true, string.Join("; ", s.Result.Warnings)));
    }

    [Fact]
    public async Task Augment_NoSuchSigner_ThrowsArgumentOutOfRange()
    {
        using var pki = new OfflinePki();
        byte[] cosigned = await CoSignedBasic(pki);

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => CadesAugmenter.Signature(cosigned, _data).ForSigner(2)
            .WithTimestamp(pki.Timestamp).ToLevel(AdesBaselineLevel.Timestamped).AugmentAsync());
        Assert.Throws<ArgumentOutOfRangeException>(() => CadesAugmenter.Signature(cosigned).ForSigner(-1));
        Assert.Throws<ArgumentOutOfRangeException>(() => CadesAugmenter.LevelOf(cosigned, 2));
    }

    /// <summary>An RSA B-B signature of <see cref="_data"/> co-signed by an ECDSA B-B one (detached).</summary>
    private async Task<byte[]> CoSignedBasic(OfflinePki pki)
    {
        byte[] rsa = await CadesSigner.Document(_data).WithCertificate(pki.Pki.Leaf, pki.Chain).SignAsync();
        return await CadesSigner.CoSign(rsa, _data).WithCertificate(pki.Ecdsa, pki.Chain).SignAsync();
    }

    private static CadesSignatureValidator OfflineValidator() =>
        new(new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false });

    /// <summary>The encoded SignerInfos of a SignedData, in order.</summary>
    private static List<byte[]> SignerInfos(byte[] cms)
    {
        var contentInfo = new AsnReader(cms, AsnEncodingRules.BER).ReadSequence();
        _ = contentInfo.ReadObjectIdentifier();
        var signedData = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)).ReadSequence();
        _ = signedData.ReadInteger();
        _ = signedData.ReadEncodedValue(); // digestAlgorithms
        _ = signedData.ReadEncodedValue(); // encapContentInfo
        while (signedData.PeekTag().TagClass == TagClass.ContextSpecific)
        {
            _ = signedData.ReadEncodedValue(); // certificates, crls
        }

        return ReadAll(signedData.ReadSetOf(skipSortOrderValidation: true));
    }

    /// <summary>The unsigned attributes of a SignerInfo, as (encoded attrType, encoded values).</summary>
    private static List<(byte[] Type, List<byte[]> Values)> UnsignedAttributes(byte[] signerInfo)
    {
        var fields = new AsnReader(signerInfo, AsnEncodingRules.BER).ReadSequence();
        var attributes = new List<(byte[], List<byte[]>)>();
        while (fields.HasData)
        {
            if (fields.PeekTag() != new Asn1Tag(TagClass.ContextSpecific, 1, true))
            {
                _ = fields.ReadEncodedValue();
                continue;
            }

            var set = fields.ReadSetOf(skipSortOrderValidation: true, new Asn1Tag(TagClass.ContextSpecific, 1, true));
            while (set.HasData)
            {
                var attribute = set.ReadSequence();
                attributes.Add((attribute.ReadEncodedValue().ToArray(), ReadAll(attribute.ReadSetOf(skipSortOrderValidation: true))));
            }
        }

        return attributes;
    }

    private static HashSet<string> UnsignedAttributeValueDigests(byte[] signerInfo) =>
        [.. UnsignedAttributes(signerInfo).SelectMany(a => a.Values.Select(v => Convert.ToHexString(SHA256.HashData([.. a.Type, .. v]))))];

    /// <summary>The unsigned attribute digests listed by the ATSHashIndexV3 of every archive-time-stamp-v3 of a SignerInfo.</summary>
    private static List<string> IndexedUnsignedAttributeDigests(byte[] signerInfo)
    {
        byte[] archiveType = Encode(w => w.WriteObjectIdentifier(Oids.ArchiveTimeStampV3));
        var tokens = UnsignedAttributes(signerInfo).Where(a => a.Type.AsSpan().SequenceEqual(archiveType)).SelectMany(a => a.Values).ToList();
        Assert.NotEmpty(tokens);
        byte[] indexType = Encode(w => w.WriteObjectIdentifier(Oids.AtsHashIndexV3));
        var digests = new List<string>();
        foreach (byte[] token in tokens)
        {
            byte[] tokenSignerInfo = Assert.Single(SignerInfos(token));
            byte[] index = UnsignedAttributes(tokenSignerInfo).Single(a => a.Type.AsSpan().SequenceEqual(indexType)).Values.Single();
            var hashIndex = new AsnReader(index, AsnEncodingRules.DER).ReadSequence();
            _ = hashIndex.ReadEncodedValue(); // hashIndAlgorithm
            _ = hashIndex.ReadEncodedValue(); // certificatesHashIndex
            _ = hashIndex.ReadEncodedValue(); // crlsHashIndex
            var unsigned = hashIndex.ReadSequence();
            while (unsigned.HasData)
            {
                digests.Add(Convert.ToHexString(unsigned.ReadOctetString()));
            }
        }

        return digests;
    }

    private static List<byte[]> ReadAll(AsnReader set)
    {
        var values = new List<byte[]>();
        while (set.HasData)
        {
            values.Add(set.ReadEncodedValue().ToArray());
        }

        return values;
    }

    private static byte[] Encode(Action<AsnWriter> write)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        write(writer);
        return writer.Encode();
    }

    private static string? FindOpenSsl() =>
        (Environment.GetEnvironmentVariable("PATH") ?? string.Empty)
            .Split(Path.PathSeparator)
            .Select(d => Path.Combine(d, OperatingSystem.IsWindows() ? "openssl.exe" : "openssl"))
            .FirstOrDefault(File.Exists);
}
