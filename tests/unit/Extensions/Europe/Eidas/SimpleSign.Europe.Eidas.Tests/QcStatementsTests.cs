using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;

namespace SimpleSign.Europe.Eidas.Tests;

[Trait("Category", "Unit")]
public sealed class QcStatementsTests
{
    [Fact]
    public void Decode_EncodedStatements_ReadsComplianceSscdAndType()
    {
        using var certificate = Certificate(QcStatements.Encode(compliance: true, sscd: true, QcStatements.ESealOid));

        var statements = QcStatements.Decode(certificate);

        statements.Present.ShouldBeTrue();
        statements.QcCompliance.ShouldBeTrue();
        statements.QcSscd.ShouldBeTrue();
        statements.Types.ShouldBe([QcStatements.ESealOid]);
        statements.Legislations.ShouldBeEmpty();
    }

    [Fact]
    public void Decode_NoExtension_IsNone()
    {
        using var certificate = Certificate(null);

        QcStatements.Decode(certificate).ShouldBeSameAs(QcStatements.None);
    }

    [Fact]
    public void Decode_MalformedExtension_KeepsWhatItRead()
    {
        using var certificate = Certificate([0x30, 0x03, 0x30, 0x01]);

        QcStatements.Decode(certificate).Present.ShouldBeTrue();
    }

    private static X509Certificate2 Certificate(byte[]? qcStatements)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=Holder", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        if (qcStatements is not null)
        {
            request.CertificateExtensions.Add(new X509Extension(QcStatements.ExtensionOid, qcStatements, false));
        }

        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }
}
