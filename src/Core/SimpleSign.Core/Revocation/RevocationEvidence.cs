using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;

namespace SimpleSign.Core.Revocation;

/// <summary>
/// Format-neutral helpers over collected revocation evidence: the certification path, the CRLs and
/// OCSP responses that cover a certificate, and the identifiers (RFC 5126 / XAdES) of each.
/// Shared by CAdES and XAdES.
/// </summary>
internal static class RevocationEvidence
{
    private static readonly Asn1Tag Context0 = new(TagClass.ContextSpecific, 0, true);

    /// <summary>The certification path, signer first, root last, built from the collected certificates.</summary>
    internal static List<X509Certificate2> BuildPath(X509Certificate2 signer, IEnumerable<byte[]> certificates)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;
        foreach (byte[] raw in certificates)
        {
            chain.ChainPolicy.ExtraStore.Add(CertificateLoader.LoadCertificate(raw));
        }

        chain.Build(signer);
        return [.. chain.ChainElements.Select(e => e.Certificate)];
    }

    /// <summary>The CRLs and OCSP responses (as given) that cover <paramref name="certificate"/>.</summary>
    internal static (List<byte[]> Crls, List<byte[]> Ocsp) CoveringEvidence(
        OcspClient ocsp, X509Certificate2 certificate, X509Certificate2? issuer, IReadOnlyList<byte[]> crls, IReadOnlyList<byte[]> ocspResponses) =>
        ([.. crls.Where(c => issuer is not null && CrlClient.IsSerialInCrl(certificate, c, issuer) is not null)],
            [.. ocspResponses.Where(r => Covers(ocsp, certificate, issuer, r))]);

    /// <summary>An OCSP client used only to match responses to certificates (no network).</summary>
    internal static OcspClient MatchingOcspClient() => new(DefaultHttpClientProvider.Instance.GetClient());

    /// <summary>The issuer (DER Name) and thisUpdate of a CRL.</summary>
    internal static (byte[] Issuer, DateTimeOffset ThisUpdate) ReadCrlIdentifier(byte[] crl)
    {
        var tbs = new AsnReader(crl, AsnEncodingRules.BER).ReadSequence().ReadSequence();
        if (tbs.PeekTag() == Asn1Tag.Integer)
        {
            _ = tbs.ReadInteger();
        }

        _ = tbs.ReadSequence(); // signature
        byte[] issuer = tbs.ReadEncodedValue().ToArray();
        DateTimeOffset thisUpdate = tbs.PeekTag().TagValue == (int)UniversalTagNumber.UtcTime ? tbs.ReadUtcTime() : tbs.ReadGeneralizedTime();
        return (issuer, thisUpdate);
    }

    /// <summary>The ResponderID (DER, [1] byName or [2] byKey) and producedAt of a BasicOCSPResponse.</summary>
    internal static (byte[] ResponderId, DateTimeOffset ProducedAt) ReadOcspIdentifier(byte[] basicResponse)
    {
        var tbs = new AsnReader(basicResponse, AsnEncodingRules.BER).ReadSequence().ReadSequence();
        if (tbs.PeekTag() == Context0)
        {
            _ = tbs.ReadEncodedValue(); // version
        }

        byte[] responderId = tbs.ReadEncodedValue().ToArray();
        return (responderId, tbs.ReadGeneralizedTime());
    }

    private static bool Covers(OcspClient client, X509Certificate2 certificate, X509Certificate2? issuer, byte[] response)
    {
        try
        {
            return client.CheckEmbeddedOcspResponse(certificate, issuer, response, null) is not null;
        }
        catch (Exception ex) when (ex is AsnContentException or CryptographicException or InvalidDataException)
        {
            return false;
        }
    }

    /// <summary>The BasicOCSPResponse inside an OCSPResponse (or the input when it already is one).</summary>
    internal static byte[] BasicResponse(byte[] response)
    {
        var outer = new AsnReader(response, AsnEncodingRules.BER).ReadSequence();
        if (outer.PeekTag().TagValue != (int)UniversalTagNumber.Enumerated)
        {
            return response; // already a BasicOCSPResponse
        }

        _ = outer.ReadEnumeratedBytes();
        var responseBytes = outer.ReadSequence(Context0).ReadSequence();
        _ = responseBytes.ReadObjectIdentifier();
        return responseBytes.ReadOctetString();
    }
}
