using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Brasil.Tests;

/// <summary>
/// A three-level synthetic PKI (root → AC → end entity) shaped like ICP-Brasil: the end entity
/// carries an A3 certificate policy (2.16.76.1.2.3.x) and a CRL distribution point.
/// </summary>
internal sealed class TestPki : IDisposable
{
    internal const string AcCrlUrl = "http://lcr.test/ac.crl";
    internal const string RootCrlUrl = "http://lcr.test/raiz.crl";

    private TestPki(X509Certificate2 root, X509Certificate2 ac, X509Certificate2 leaf)
    {
        Root = root;
        Ac = ac;
        Leaf = leaf;
    }

    internal X509Certificate2 Root { get; }

    internal X509Certificate2 Ac { get; }

    internal X509Certificate2 Leaf { get; }

    /// <summary>When the end entity expired (one day ago).</summary>
    internal static DateTimeOffset LeafNotAfter => DateTimeOffset.UtcNow.Date.AddDays(-1);

    /// <summary>A time when the end entity was valid (one year ago).</summary>
    internal static DateTimeOffset WhileValid => DateTimeOffset.UtcNow.Date.AddYears(-1);

    internal static TestPki Create(string policyOid = "2.16.76.1.2.3.10", bool leafExpired = true, params (string Oid, string Value)[] subjectAltNames)
    {
        var now = DateTimeOffset.UtcNow.Date;
        using var rootKey = RSA.Create(2048);
        var rootReq = new CertificateRequest("CN=Test AC Raiz, O=ICP-Brasil Test, C=BR", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        AddCaExtensions(rootReq);
        var root = rootReq.CreateSelfSigned(now.AddYears(-10), now.AddYears(10));

        using var acKey = RSA.Create(2048);
        var acReq = new CertificateRequest("CN=Test AC Final, O=ICP-Brasil Test, C=BR", acKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        AddCaExtensions(acReq);
        acReq.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([RootCrlUrl]));
        using var acPublic = acReq.Create(root, now.AddYears(-8), now.AddYears(8), [0x10, 0x01]);
        var ac = acPublic.CopyWithPrivateKey(acKey);

        using var leafKey = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=FULANO DE TAL:12345678909, O=ICP-Brasil Test, C=BR", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        leafReq.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([AcCrlUrl]));
        leafReq.CertificateExtensions.Add(CertificatePolicies(policyOid));
        if (subjectAltNames.Length > 0)
        {
            leafReq.CertificateExtensions.Add(SanCertificates.OtherNames(subjectAltNames));
        }

        using var leafPublic = leafReq.Create(ac, now.AddYears(-3), leafExpired ? LeafNotAfter : now.AddYears(1), [0x20, 0x02]);
        var leaf = leafPublic.CopyWithPrivateKey(leafKey);

        return new TestPki(root, ac, leaf);
    }

    /// <summary>A CRL issued by the AC, listing the end entity as revoked at <paramref name="revokedAt"/> when given.</summary>
    internal byte[] AcCrl(DateTimeOffset thisUpdate, DateTimeOffset nextUpdate, DateTimeOffset? revokedAt = null) =>
        Crl(Ac, thisUpdate, nextUpdate, revokedAt is { } at ? (Leaf, at) : null);

    /// <summary>A CRL issued by the root, listing the AC as revoked at <paramref name="revokedAt"/> when given.</summary>
    internal byte[] RootCrl(DateTimeOffset thisUpdate, DateTimeOffset nextUpdate, DateTimeOffset? revokedAt = null) =>
        Crl(Root, thisUpdate, nextUpdate, revokedAt is { } at ? (Ac, at) : null);

    public void Dispose()
    {
        Root.Dispose();
        Ac.Dispose();
        Leaf.Dispose();
    }

    private static byte[] Crl(X509Certificate2 issuer, DateTimeOffset thisUpdate, DateTimeOffset nextUpdate, (X509Certificate2 Cert, DateTimeOffset At)? revoked)
    {
        var builder = new CertificateRevocationListBuilder();
        if (revoked is { } r)
        {
            builder.AddEntry(r.Cert, r.At, X509RevocationReason.KeyCompromise);
        }

        return builder.Build(issuer, BigInteger.One, nextUpdate, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, thisUpdate);
    }

    private static void AddCaExtensions(CertificateRequest req)
    {
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
    }

    private static X509Extension CertificatePolicies(string oid)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier(oid);
            }
        }

        return new X509Extension("2.5.29.32", w.Encode(), critical: false);
    }
}
