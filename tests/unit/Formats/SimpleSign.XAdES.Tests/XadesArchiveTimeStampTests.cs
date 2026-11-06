using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using Shouldly;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES.Constants;
using Xunit;

namespace SimpleSign.XAdES.Tests;

/// <summary>The shape of the ArchiveTimeStamp element (ETSI EN 319 132-1 §5.5.2), as other validators read it.</summary>
[Trait("Category", "Unit")]
public sealed class XadesArchiveTimeStampTests : IDisposable
{
    private readonly X509Certificate2 _cert = TestCertificateFactory.CreateSelfSignedCert("CN=XAdES ATS, O=Tests");

    public void Dispose() => _cert.Dispose();

    [Fact]
    public async Task EmbedArchiveTimeStamp_Element_IsV141WithV132Children()
    {
        byte[] signed = await XadesSigner.Document(Encoding.UTF8.GetBytes("<doc><id>1</id></doc>")).WithCertificate(_cert).SignAsync();
        byte[] token = [0x30, 0x03, 0x02, 0x01, 0x01];

        byte[] withArchive = XadesSignatureBuilder.EmbedArchiveTimeStamp(signed, token);

        var document = new XmlDocument { PreserveWhitespace = true };
        document.Load(new MemoryStream(withArchive));
        var ns = new XmlNamespaceManager(document.NameTable);
        ns.AddNamespace("xades", XadesUris.XadesNamespace);
        ns.AddNamespace("xades141", XadesUris.Xades141Namespace);
        // ArchiveTimeStamp was added in XAdES v1.4.1; its type (XAdESTimeStampType) and so its
        // children belong to v1.3.2. A token in the v1.4.1 namespace is invisible to EU DSS.
        var archive = document.SelectSingleNode("//xades:UnsignedSignatureProperties/xades141:ArchiveTimeStamp", ns).ShouldNotBeNull();
        archive.SelectSingleNode("xades:EncapsulatedTimeStamp", ns).ShouldNotBeNull().InnerText.ShouldBe(Convert.ToBase64String(token));
        archive.SelectSingleNode("xades141:EncapsulatedTimeStamp", ns).ShouldBeNull();
        XadesSignatureBuilder.ExtractArchiveTimeStamp(withArchive).ShouldBe(token);
    }

    [Fact]
    public async Task ExtractArchiveTimeStamp_TokenInTheV141Namespace_IsStillRead()
    {
        byte[] signed = await XadesSigner.Document(Encoding.UTF8.GetBytes("<doc><id>1</id></doc>")).WithCertificate(_cert).SignAsync();
        byte[] token = [0x30, 0x03, 0x02, 0x01, 0x01];
        string current = Encoding.UTF8.GetString(XadesSignatureBuilder.EmbedArchiveTimeStamp(signed, token));
        var document = new XmlDocument { PreserveWhitespace = true };
        document.LoadXml(current);
        var ns = new XmlNamespaceManager(document.NameTable);
        ns.AddNamespace("xades", XadesUris.XadesNamespace);
        ns.AddNamespace("xades141", XadesUris.Xades141Namespace);
        var archive = (XmlElement)document.SelectSingleNode("//xades141:ArchiveTimeStamp", ns)!;
        var old = archive.SelectSingleNode("xades:EncapsulatedTimeStamp", ns)!;
        var legacy = document.CreateElement("EncapsulatedTimeStamp", XadesUris.Xades141Namespace);
        legacy.InnerText = old.InnerText;
        archive.ReplaceChild(legacy, old);
        using var stream = new MemoryStream();
        document.Save(stream);

        XadesSignatureBuilder.ExtractArchiveTimeStamp(stream.ToArray()).ShouldBe(token);
    }
}
