using Shouldly;
using SimpleSign.Cli.Rendering;
using SimpleSign.Core.Inspection;
using SimpleSign.PAdES.Inspection;

namespace SimpleSign.Cli.Tests;

[Trait("Category", "Unit")]
public sealed class InspectOutputRendererTests
{
    [Fact]
    public void RenderJson_IncludesBasicFields()
    {
        var sig = CreateSignatureFieldInfo();

        var json = InspectOutputRenderer.RenderJson(sig, false);

        json.ShouldContain("\"fieldName\": \"TestSig\"");
        json.ShouldContain("\"subFilter\": \"ETSI.CAdES.detached\"");
        json.ShouldContain("\"cmsSize\": 100");
        json.ShouldContain("\"hasTimestamp\": false");
    }

    [Fact]
    public void RenderJson_WithSigner_IncludesCertFields()
    {
        var sig = CreateSignatureFieldInfo(signer: new CertificateInfo
        {
            Subject = "CN=Test",
            Issuer = "CN=CA",
            SerialNumber = "01",
            Thumbprint = "DEADBEEF",
        });

        var json = InspectOutputRenderer.RenderJson(sig, false);

        json.ShouldContain("CN=Test");
        json.ShouldContain("CN=CA");
        json.ShouldContain("DE:AD:BE:EF");
    }

    [Fact]
    public void RenderJson_WithChain_IncludesEmbeddedCertificates()
    {
        var sig = CreateSignatureFieldInfo(
            signer: new CertificateInfo { Subject = "CN=Signer", Thumbprint = "AA" },
            embedded: new List<CertificateInfo>
            {
                new CertificateInfo { Subject = "CN=Signer", Thumbprint = "AA" },
                new CertificateInfo { Subject = "CN=CA", Thumbprint = "BB" }
            });

        var json = InspectOutputRenderer.RenderJson(sig, true);

        json.ShouldContain("CN=Signer");
        json.ShouldContain("CN=CA");
    }

    [Fact]
    public void RenderJson_WithTimestamp_IncludesTimestampFields()
    {
        var sig = CreateSignatureFieldInfo(
            timestamp: new TimestampInfo
            {
                GenerationTime = new DateTimeOffset(2025, 1, 15, 12, 0, 0, TimeSpan.Zero),
                TsaCertificate = new CertificateInfo
                {
                    Subject = "CN=TSA",
                    Issuer = "CN=TSA-CA",
                    Thumbprint = "1234",
                },
            });

        var json = InspectOutputRenderer.RenderJson(sig, false);

        json.ShouldContain("\"hasTimestamp\": true");
        json.ShouldContain("2025-01-15T12:00:00");
        json.ShouldContain("CN=TSA");
    }

    [Fact]
    public void BuildTree_ReturnsTreeWithSignatureInfo()
    {
        var sig = CreateSignatureFieldInfo();
        var tree = InspectOutputRenderer.BuildTree(sig);

        tree.ShouldNotBeNull();
    }

    private static SignatureFieldInfo CreateSignatureFieldInfo(
        CertificateInfo? signer = null,
        TimestampInfo? timestamp = null,
        List<CertificateInfo>? embedded = null)
    {
        return new SignatureFieldInfo
        {
            FieldName = "TestSig",
            SubFilter = "ETSI.CAdES.detached",
            Signer = signer,
            Timestamp = timestamp,
            EmbeddedCertificates = embedded ?? new List<CertificateInfo>(),
            CmsRawData = new byte[100],
            ByteRange = new SimpleSign.PAdES.Pdf.PdfByteRange { Offset1 = 0, Length1 = 50, Offset2 = 100, Length2 = 30 },
            SigningTime = null,
            Reason = "Approval",
            Location = "Office",
        };
    }
}
