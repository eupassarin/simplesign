using SimpleSign.HostSigner.Services;
using SimpleSign.PAdES.Inspection;
using CoreCertInfo = SimpleSign.Core.Inspection.CertificateInfo;
using SimpleSign.Core.Inspection;
using SimpleSign.Pdf;
using SimpleSign.Pdf.Enums;
using Xunit;

namespace SimpleSign.HostSigner.Tests.Services;

public class InspectMapperTests
{
    [Theory]
    [InlineData("SHA-256", "1.2.840.113549.1.1.11", "SHA-256 (1.2.840.113549.1.1.11)")]
    [InlineData("SHA-256", null, "SHA-256")]
    [InlineData(null, "1.2.840.113549.1.1.11", "1.2.840.113549.1.1.11")]
    [InlineData(null, null, "unknown")]
    [InlineData("", "", "unknown")]
    public void Map_Signature_DigestAlgorithmFormatsCorrectly(string? name, string? oid, string expected)
    {
        var sig = new SignatureFieldInfo
        {
            FieldName = "Sig1",
            DigestAlgorithm = new AlgorithmInfo { Name = name ?? "", Oid = oid ?? "" },
            SignatureAlgorithm = new AlgorithmInfo { Name = "", Oid = "" },
            ByteRange = new PdfByteRange(),
            CmsRawData = new byte[10]
        };
        var result = InspectMapper.Map(new PdfInspectionResult
        {
            Document = new PdfDocumentInfo(),
            Signatures = [sig]
        });

        var dto = result.Signatures[0];
        Assert.Equal(expected, dto.DigestAlgorithm);
    }

    [Theory]
    [InlineData(false, false, false, "CMS (no PAdES)")]
    [InlineData(true, false, false, "PAdES B-B")]
    [InlineData(true, true, false, "PAdES B-T")]
    [InlineData(true, true, true, "PAdES B-LT")]
    public void Map_Signature_LevelFormatsCorrectly(
        bool hasSigningCertV2, bool hasTimestamp, bool hasDss, string expected)
    {
        var sig = new SignatureFieldInfo
        {
            FieldName = "Sig1",
            HasSigningCertificateV2 = hasSigningCertV2,
            Timestamp = hasTimestamp ? new TimestampInfo { GenerationTime = DateTimeOffset.UtcNow } : null,
            DigestAlgorithm = new AlgorithmInfo(),
            SignatureAlgorithm = new AlgorithmInfo(),
            ByteRange = new PdfByteRange(),
            CmsRawData = new byte[10]
        };
        var doc = new PdfDocumentInfo
        {
            SecurityStore = hasDss ? new DssInfo { CertificateCount = 1 } : null
        };
        var result = InspectMapper.Map(new PdfInspectionResult
        {
            Document = doc,
            Signatures = [sig]
        });

        Assert.Equal(expected, result.Signatures[0].Level);
    }

    [Fact]
    public void Map_Signature_Level_BaselineLTA()
    {
        var sig = new SignatureFieldInfo
        {
            FieldName = "Sig1",
            HasSigningCertificateV2 = true,
            Timestamp = new TimestampInfo { GenerationTime = DateTimeOffset.UtcNow },
            DigestAlgorithm = new AlgorithmInfo(),
            SignatureAlgorithm = new AlgorithmInfo(),
            ByteRange = new PdfByteRange { Offset2 = 100 },
            CmsRawData = new byte[10]
        };
        var docTs = new SignatureFieldInfo
        {
            FieldName = "DocTS",
            SubFilter = "ETSI.RFC3161",
            DigestAlgorithm = new AlgorithmInfo(),
            SignatureAlgorithm = new AlgorithmInfo(),
            ByteRange = new PdfByteRange { Offset2 = 200 },
            CmsRawData = new byte[10]
        };
        var doc = new PdfDocumentInfo
        {
            SecurityStore = new DssInfo { CertificateCount = 1 }
        };
        var result = InspectMapper.Map(new PdfInspectionResult
        {
            Document = doc,
            Signatures = [sig, docTs]
        });

        Assert.Equal("PAdES B-LTA", result.Signatures[0].Level);
    }

    [Theory]
    [InlineData(PdfALevel.None, "Not detected")]
    [InlineData(PdfALevel.A1a, "PDF/A-1a (ISO 19005-1)")]
    [InlineData(PdfALevel.A1b, "PDF/A-1b (ISO 19005-1)")]
    [InlineData(PdfALevel.A2a, "PDF/A-2a (ISO 19005-2)")]
    [InlineData(PdfALevel.A2b, "PDF/A-2b (ISO 19005-2)")]
    [InlineData(PdfALevel.A2u, "PDF/A-2u (ISO 19005-2)")]
    [InlineData(PdfALevel.A3a, "PDF/A-3a (ISO 19005-3)")]
    [InlineData(PdfALevel.A3b, "PDF/A-3b (ISO 19005-3)")]
    [InlineData(PdfALevel.A3u, "PDF/A-3u (ISO 19005-3)")]
    [InlineData(PdfALevel.A4a, "PDF/A-4a (ISO 19005-4)")]
    [InlineData(PdfALevel.A4b, "PDF/A-4b (ISO 19005-4)")]
    [InlineData(PdfALevel.A4u, "PDF/A-4u (ISO 19005-4)")]
    [InlineData(PdfALevel.A4e, "PDF/A-4e (ISO 19005-4)")]
    public void Map_Document_PdfAFormatsCorrectly(PdfALevel level, string expected)
    {
        var doc = new PdfDocumentInfo { PdfALevel = level };
        var result = InspectMapper.Map(new PdfInspectionResult
        {
            Document = doc,
            Signatures = []
        });

        Assert.Equal(expected, result.Document.PdfA);
    }

    [Fact]
    public void Map_Cert_NullSigner_ReturnsNull()
    {
        var sig = new SignatureFieldInfo
        {
            FieldName = "Sig1",
            DigestAlgorithm = new AlgorithmInfo(),
            SignatureAlgorithm = new AlgorithmInfo(),
            ByteRange = new PdfByteRange(),
            CmsRawData = new byte[10],
            Signer = null
        };
        var result = InspectMapper.Map(new PdfInspectionResult
        {
            Document = new PdfDocumentInfo(),
            Signatures = [sig]
        });

        Assert.Null(result.Signatures[0].Signer);
    }

    [Fact]
    public void Map_Cert_FullModeIncludesExtendedFields()
    {
        var cert = new CoreCertInfo
        {
            Subject = "CN=Test",
            Issuer = "CN=CA",
            SerialNumber = "01",
            Thumbprint = "thumb",
            KeyAlgorithm = "RSA",
            KeySizeBits = 2048,
            HasNonRepudiation = true,
            NotBefore = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            NotAfter = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            KeyUsages = ["Digital Signature"],
            ExtendedKeyUsages = [],
            OcspUrl = "http://ocsp.test",
            CrlUrl = "http://crl.test",
            AiaUrls = ["http://aia.test"]
        };
        var sig = new SignatureFieldInfo
        {
            FieldName = "Sig1",
            DigestAlgorithm = new AlgorithmInfo(),
            SignatureAlgorithm = new AlgorithmInfo(),
            ByteRange = new PdfByteRange(),
            CmsRawData = new byte[10],
            Signer = cert
        };
        var result = InspectMapper.Map(new PdfInspectionResult
        {
            Document = new PdfDocumentInfo(),
            Signatures = [sig]
        });

        var dto = result.Signatures[0].Signer!;
        Assert.Equal("CN=Test", dto.Subject);
        Assert.Equal("CN=CA", dto.Issuer);
        Assert.Equal("01", dto.SerialNumber);
        Assert.Equal("thumb", dto.Thumbprint);
        Assert.Equal("RSA", dto.KeyAlgorithm);
        Assert.Equal(2048, dto.KeySizeBits);
        Assert.True(dto.HasNonRepudiation);
        Assert.Equal(["Digital Signature"], dto.KeyUsages);
        Assert.Empty(dto.ExtendedKeyUsages);
        Assert.Equal("http://ocsp.test", dto.OcspUrl);
        Assert.Equal("http://crl.test", dto.CrlUrl);
        Assert.Equal(["http://aia.test"], dto.AiaUrls);
    }

    [Fact]
    public void Map_Signature_TimestampMapsCorrectly()
    {
        var tsaCert = new CoreCertInfo
        {
            Subject = "CN=TSA",
            Issuer = "CN=TSA-CA"
        };
        var ts = new TimestampInfo
        {
            GenerationTime = new DateTimeOffset(2025, 6, 1, 12, 0, 0, TimeSpan.Zero),
            TsaCertificate = tsaCert,
            HashAlgorithm = new AlgorithmInfo { Name = "SHA-256", Oid = "2.16.840.1.101.3.4.2.1" },
            PolicyOid = "1.2.3.4",
            SerialNumber = "12345",
            RawToken = new byte[100]
        };
        var sig = new SignatureFieldInfo
        {
            FieldName = "Sig1",
            DigestAlgorithm = new AlgorithmInfo(),
            SignatureAlgorithm = new AlgorithmInfo(),
            ByteRange = new PdfByteRange(),
            CmsRawData = new byte[10],
            Timestamp = ts
        };
        var result = InspectMapper.Map(new PdfInspectionResult
        {
            Document = new PdfDocumentInfo(),
            Signatures = [sig]
        });

        var tsDto = result.Signatures[0].Timestamp!;
        Assert.Equal(ts.GenerationTime, tsDto.Time);
        Assert.Equal("CN=TSA", tsDto.TsaSubject);
        Assert.Equal("CN=TSA-CA", tsDto.TsaIssuer);
        Assert.Equal("SHA-256 (2.16.840.1.101.3.4.2.1)", tsDto.HashAlgorithm);
        Assert.Equal("1.2.3.4", tsDto.PolicyOid);
        Assert.Equal("12345", tsDto.SerialNumber);
        Assert.Equal(100, tsDto.TokenSize);
    }

    [Fact]
    public void Map_Signature_EmbeddedCertificatesMapped()
    {
        var embedded = new List<CoreCertInfo>
        {
            new() { Subject = "CN=Signer", Issuer = "CN=CA1", SerialNumber = "01" },
            new() { Subject = "CN=CA1", Issuer = "CN=Root", SerialNumber = "02" }
        };
        var sig = new SignatureFieldInfo
        {
            FieldName = "Sig1",
            DigestAlgorithm = new AlgorithmInfo(),
            SignatureAlgorithm = new AlgorithmInfo(),
            ByteRange = new PdfByteRange(),
            CmsRawData = new byte[10],
            EmbeddedCertificates = embedded
        };
        var result = InspectMapper.Map(new PdfInspectionResult
        {
            Document = new PdfDocumentInfo(),
            Signatures = [sig]
        });

        var certs = result.Signatures[0].EmbeddedCertificates;
        Assert.Equal(2, certs.Count);
        Assert.Equal("CN=Signer", certs[0].Subject);
        Assert.Equal("CN=CA1", certs[1].Subject);
    }

    [Fact]
    public void Map_ByteRange_MapsCorrectly()
    {
        var br = new PdfByteRange
        {
            Offset1 = 0,
            Length1 = 100,
            Offset2 = 200,
            Length2 = 50
        };
        var sig = new SignatureFieldInfo
        {
            FieldName = "Sig1",
            DigestAlgorithm = new AlgorithmInfo(),
            SignatureAlgorithm = new AlgorithmInfo(),
            ByteRange = br,
            CmsRawData = new byte[10]
        };
        var result = InspectMapper.Map(new PdfInspectionResult
        {
            Document = new PdfDocumentInfo(),
            Signatures = [sig]
        });

        var brDto = result.Signatures[0].ByteRange;
        Assert.Equal(0, brDto.Offset1);
        Assert.Equal(100, brDto.Length1);
        Assert.Equal(200, brDto.Offset2);
        Assert.Equal(50, brDto.Length2);
    }

    [Fact]
    public void Map_Document_SignatureCount()
    {
        var sigs = new[]
        {
            new SignatureFieldInfo
            {
                FieldName = "Sig1",
                DigestAlgorithm = new AlgorithmInfo(),
                SignatureAlgorithm = new AlgorithmInfo(),
                ByteRange = new PdfByteRange(),
                CmsRawData = new byte[10]
            }
        };
        var doc = new PdfDocumentInfo { SignatureCount = sigs.Length };
        var result = InspectMapper.Map(new PdfInspectionResult
        {
            Document = doc,
            Signatures = sigs
        });

        Assert.Equal(1, result.Document.SignatureCount);
    }

    [Fact]
    public void Map_Document_EncryptedFlag()
    {
        var doc = new PdfDocumentInfo { IsEncrypted = true };
        var result = InspectMapper.Map(new PdfInspectionResult
        {
            Document = doc,
            Signatures = []
        });

        Assert.True(result.Document.Encrypted);
    }

    [Fact]
    public void Map_Document_DocMdpFields()
    {
        var doc = new PdfDocumentInfo
        {
            IsDocMdpLocked = true,
            DocMdpPermissionLevel = 2
        };
        var result = InspectMapper.Map(new PdfInspectionResult
        {
            Document = doc,
            Signatures = []
        });

        Assert.True(result.Document.DocMdpLocked);
        Assert.Equal(2, result.Document.DocMdpLevel);
    }

    [Fact]
    public void Map_Document_DssPresent()
    {
        var doc = new PdfDocumentInfo
        {
            SecurityStore = new DssInfo
            {
                CertificateCount = 3,
                CrlCount = 1,
                OcspResponseCount = 2,
                HasVri = true
            }
        };
        var result = InspectMapper.Map(new PdfInspectionResult
        {
            Document = doc,
            Signatures = []
        });

        var dss = result.Document.Dss!;
        Assert.True(dss.Present);
        Assert.Equal(3, dss.Certificates);
        Assert.Equal(1, dss.Crls);
        Assert.Equal(2, dss.Ocsps);
        Assert.True(dss.HasVri);
    }

    [Fact]
    public void Map_Document_DssNull_WhenSecurityStoreNull()
    {
        var doc = new PdfDocumentInfo();
        var result = InspectMapper.Map(new PdfInspectionResult
        {
            Document = doc,
            Signatures = []
        });

        Assert.Null(result.Document.Dss);
    }

    [Fact]
    public void Map_Signature_MetadataFields()
    {
        var sig = new SignatureFieldInfo
        {
            FieldName = "Sig1",
            DigestAlgorithm = new AlgorithmInfo(),
            SignatureAlgorithm = new AlgorithmInfo(),
            ByteRange = new PdfByteRange(),
            CmsRawData = new byte[10],
            Reason = "Approved",
            Location = "Office",
            ContactInfo = "user@test.com",
            DeclaredSignerName = "John Doe",
            CommitmentTypeOid = "1.2.840.113549.1.9.16.6.2",
            SignaturePolicyOid = "2.16.76.1.11.1",
            SubFilter = "ETSI.CAdES.detached",
            HasSigningCertificateV2 = true,
            SigningTime = new DateTimeOffset(2025, 6, 1, 10, 0, 0, TimeSpan.Zero),
            PdfDeclaredSigningTime = new DateTimeOffset(2025, 6, 1, 10, 0, 0, TimeSpan.Zero)
        };
        var result = InspectMapper.Map(new PdfInspectionResult
        {
            Document = new PdfDocumentInfo(),
            Signatures = [sig]
        });

        var dto = result.Signatures[0];
        Assert.Equal("Sig1", dto.FieldName);
        Assert.Equal("Approved", dto.Reason);
        Assert.Equal("Office", dto.Location);
        Assert.Equal("user@test.com", dto.ContactInfo);
        Assert.Equal("John Doe", dto.DeclaredSignerName);
        Assert.Equal("1.2.840.113549.1.9.16.6.2", dto.CommitmentTypeOid);
        Assert.Equal("2.16.76.1.11.1", dto.SignaturePolicyOid);
        Assert.Equal("ETSI.CAdES.detached", dto.SubFilter);
        Assert.True(dto.HasSigningCertificateV2);
        Assert.Equal(sig.SigningTime, dto.SigningTime);
        Assert.Equal(10, dto.CmsDataSize);
    }

    [Fact]
    public void Map_MultipleSignatures_MappedInOrder()
    {
        var sigs = new[]
        {
            new SignatureFieldInfo
            {
                FieldName = "Sig1",
                DigestAlgorithm = new AlgorithmInfo(),
                SignatureAlgorithm = new AlgorithmInfo(),
                ByteRange = new PdfByteRange(),
                CmsRawData = new byte[10]
            },
            new SignatureFieldInfo
            {
                FieldName = "Sig2",
                DigestAlgorithm = new AlgorithmInfo(),
                SignatureAlgorithm = new AlgorithmInfo(),
                ByteRange = new PdfByteRange(),
                CmsRawData = new byte[20]
            }
        };
        var result = InspectMapper.Map(new PdfInspectionResult
        {
            Document = new PdfDocumentInfo(),
            Signatures = sigs
        });

        Assert.Equal(2, result.Signatures.Count);
        Assert.Equal("Sig1", result.Signatures[0].FieldName);
        Assert.Equal("Sig2", result.Signatures[1].FieldName);
    }

    [Fact]
    public void Map_Timestamp_Null_WhenNoTimestamp()
    {
        var sig = new SignatureFieldInfo
        {
            FieldName = "Sig1",
            DigestAlgorithm = new AlgorithmInfo(),
            SignatureAlgorithm = new AlgorithmInfo(),
            ByteRange = new PdfByteRange(),
            CmsRawData = new byte[10],
            Timestamp = null
        };
        var result = InspectMapper.Map(new PdfInspectionResult
        {
            Document = new PdfDocumentInfo(),
            Signatures = [sig]
        });

        Assert.Null(result.Signatures[0].Timestamp);
    }
}
