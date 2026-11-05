using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Brasil.Tests;

/// <summary>Builds self-signed test certificates with ICP-Brasil style SubjectAltName otherNames.</summary>
internal static class SanCertificates
{
    internal static X509Certificate2 Create(params (string Oid, string Value)[] otherNames)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            foreach (var (oid, value) in otherNames)
            {
                using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
                {
                    w.WriteObjectIdentifier(oid);
                    using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
                    {
                        w.WriteCharacterString(UniversalTagNumber.UTF8String, value);
                    }
                }
            }
        }

        using var key = RSA.Create(2048);
        var req = new CertificateRequest("CN=SanTest", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509Extension("2.5.29.17", w.Encode(), critical: false));
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }
}
