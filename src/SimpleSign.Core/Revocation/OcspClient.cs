using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;

namespace SimpleSign.Core.Revocation;

/// <summary>
/// OCSP (Online Certificate Status Protocol) client for certificate revocation checking.
/// Builds OCSP requests, sends them, and verifies response signatures.
/// </summary>
internal sealed class OcspClient
{
    private readonly HttpClient _httpClient;
    private readonly ILogger _logger;

    public OcspClient(HttpClient httpClient, ILogger? logger = null)
    {
        _httpClient = httpClient;
        _logger = logger ?? NullLogger.Instance;
    }

    #region Instance methods

    internal async Task<bool> CheckOcspAsync(X509Certificate2 cert, string ocspUrl, CancellationToken ct)
    {
        var (isValid, _) = await FetchOcspResponseAsync(cert, issuerCert: null, ocspUrl, ct).ConfigureAwait(false);
        return isValid;
    }

    internal async Task<bool> CheckOcspWithChainAsync(
        X509Certificate2 cert,
        IReadOnlyList<X509Certificate2> chain,
        string ocspUrl,
        CancellationToken ct)
    {
        var issuerCert = chain.FirstOrDefault(c => c.Subject == cert.Issuer);
        var (isValid, _) = await FetchOcspResponseAsync(cert, issuerCert, ocspUrl, ct).ConfigureAwait(false);
        return isValid;
    }

    /// <summary>
    /// Fetches an OCSP response and returns both the revocation status and the raw response bytes.
    /// The raw bytes can be embedded in the PDF DSS dictionary for LTV (Long-Term Validation).
    /// </summary>
    internal async Task<(bool IsValid, byte[] ResponseBytes)> FetchOcspResponseAsync(
        X509Certificate2 cert,
        X509Certificate2? issuerCert,
        string ocspUrl,
        CancellationToken ct)
    {
        byte[] ocspRequest = BuildOcspRequest(cert, issuerCert);
        using var content = new ByteArrayContent(ocspRequest);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/ocsp-request");

        _logger.OcspRequestSending(ocspUrl);
        using var response = await ResilientHttp.PostAsync(_httpClient, ocspUrl, content, ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"OCSP responder returned HTTP {(int)response.StatusCode}");
        }

        byte[] ocspResponse = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        _logger.OcspResponseReceived(ocspResponse.Length);
        bool isValid = ParseOcspResponse(ocspResponse, cert, _logger);
        return (isValid, ocspResponse);
    }
    #endregion

    #region Static methods

    /// <summary>
    /// Builds a minimal OCSPRequest (RFC 2560) for the provided certificate.
    /// CertID uses SHA-1 (required by RFC — not the document digest).
    ///
    /// issuerKeyHash = SHA-1(issuer public key BIT STRING value)
    /// If issuerCert is not provided, uses the subject's own public key as an approximation
    /// (less precise, but avoids silent rejection by the OCSP server).
    /// </summary>
    internal static byte[] BuildOcspRequest(X509Certificate2 cert, X509Certificate2? issuerCert)
    {
        // CertID = { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }
        // issuerNameHash = SHA-1(DER encoding of issuer Name)
        // issuerKeyHash  = SHA-1(issuer SubjectPublicKeyInfo.subjectPublicKey BIT STRING value)
#pragma warning disable CA5350 // OCSP RFC 2560 mandates SHA-1 for CertID
        byte[] issuerNameHash = SHA1.HashData(cert.IssuerName.RawData);
        // If we have the issuer cert, we use its key — as per RFC 2560.
        // Otherwise, we use the cert's own key (acceptable fallback for servers
        // that only look up by serial+issuerName, ignoring issuerKeyHash).
        byte[] issuerKeyHash = issuerCert is not null
            ? SHA1.HashData(ExtractPublicKeyBytes(issuerCert))
            : SHA1.HashData(ExtractPublicKeyBytes(cert));
#pragma warning restore CA5350

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence()) // OCSPRequest
        {
            using (writer.PushSequence()) // TBSRequest
            {
                using (writer.PushSequence()) // requestList
                {
                    using (writer.PushSequence()) // Request
                    {
                        using (writer.PushSequence()) // CertID
                        {
                            // hashAlgorithm AlgorithmIdentifier { SHA-1 }
                            using (writer.PushSequence())
                            {
                                writer.WriteObjectIdentifier(Oids.Sha1); // SHA-1
                                writer.WriteNull();
                            }
                            writer.WriteOctetString(issuerNameHash); // issuerNameHash
                            writer.WriteOctetString(issuerKeyHash);  // issuerKeyHash
                            writer.WriteInteger(                     // serialNumber
                                new System.Numerics.BigInteger(cert.SerialNumberBytes.Span, isUnsigned: false, isBigEndian: true));
                        }
                    }
                }
            }
        }
        return writer.Encode();
    }

    /// <summary>
    /// Extracts the public key bytes (SubjectPublicKeyInfo.subjectPublicKey BIT STRING value)
    /// for computing the issuerKeyHash in OCSP.
    /// </summary>
    internal static byte[] ExtractPublicKeyBytes(X509Certificate2 cert)
    {
        // SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING }
        // We want the BIT STRING content (without the padding byte)
        var spki = cert.PublicKey.ExportSubjectPublicKeyInfo();
        var reader = new AsnReader(spki, AsnEncodingRules.DER);
        var seq = reader.ReadSequence();
        seq.ReadSequence(); // AlgorithmIdentifier
        var bitString = seq.ReadBitString(out _);
        return bitString.ToArray();
    }

    /// <summary>
    /// Parses an OCSPResponse (RFC 2560) and returns true if the certificate is not revoked.
    /// Validates the BasicOCSPResponse signature when possible.
    /// </summary>
    internal static bool ParseOcspResponse(byte[] ocspResponseBytes, X509Certificate2 cert, ILogger? logger = null)
    {
        var reader = new AsnReader(ocspResponseBytes, AsnEncodingRules.BER);
        var ocspResponse = reader.ReadSequence();

        // responseStatus
        var statusEncoded = ocspResponse.ReadEncodedValue().Span;
        int status = statusEncoded.Length >= 3 ? statusEncoded[2] : -1;
        if (status != 0)
        {
            throw new InvalidOperationException($"OCSP response status is not 'successful': {status}");
        }

        if (!ocspResponse.HasData)
        {
            throw new InvalidDataException("OCSP response is empty.");
        }

        // RFC 6960: responseBytes [0] EXPLICIT ResponseBytes
        // ResponseBytes ::= SEQUENCE { responseType OID, response OCTET STRING }
        // The [0] EXPLICIT wrapper holds the *encoded* inner SEQUENCE — we must unwrap
        // both layers (the [0] tag and then the SEQUENCE) before reading responseType.
        var responseBytesWrapper = ocspResponse.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        var respBytes = responseBytesWrapper.ReadSequence();

        _ = respBytes.ReadObjectIdentifier(); // responseType (id-pkix-ocsp-basic)
        var basicOcspBytes = respBytes.ReadOctetString();

        // BasicOCSPResponse ::= SEQUENCE { tbsResponseData, signatureAlgorithm, signature, [0] certs OPTIONAL }
        var basicReader = new AsnReader(basicOcspBytes, AsnEncodingRules.BER);
        var basicOcsp = basicReader.ReadSequence();

        // Keep raw tbsResponseData for signature verification
        byte[] tbsResponseDataRaw = basicOcsp.PeekEncodedValue().ToArray();
        var tbsResponseData = basicOcsp.ReadSequence();

        // signatureAlgorithm
        var sigAlgSeq = basicOcsp.ReadSequence();
        string sigAlgOid = sigAlgSeq.ReadObjectIdentifier();

        // signature BIT STRING
        byte[] ocspSignature = basicOcsp.ReadBitString(out _);

        // certs [0] OPTIONAL — extract responder cert
        X509Certificate2? responderCert = null;
#pragma warning disable CA2000 // responderCert is disposed in the finally block below
        if (basicOcsp.HasData && basicOcsp.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
        {
            var certsWrapper = basicOcsp.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
            while (certsWrapper.HasData)
            {
                try
                {
                    responderCert = CertificateLoader.LoadCertificate(certsWrapper.ReadEncodedValue().ToArray());
                    break; // use first cert
                }
                catch (CryptographicException ex) { logger?.OcspResponderCertLoadingFailed(ex.Message); certsWrapper.ReadEncodedValue(); }
            }
        }
#pragma warning restore CA2000

        try
        {
            // Verify OCSP response signature
            if (responderCert is not null)
            {
                bool sigValid = VerifyOcspSignature(responderCert, tbsResponseDataRaw, ocspSignature, sigAlgOid, logger);
                if (!sigValid)
                {
                    throw new InvalidOperationException("OCSP response signature verification failed.");
                }
            }

            // Parse tbsResponseData for cert status
            if (tbsResponseData.HasData && tbsResponseData.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true))
            {
                tbsResponseData.ReadEncodedValue(); // version
            }

            tbsResponseData.ReadEncodedValue(); // responderID
            tbsResponseData.ReadEncodedValue(); // producedAt

            var responses = tbsResponseData.ReadSequence();
            while (responses.HasData)
            {
                var single = responses.ReadSequence();
                single.ReadSequence(); // CertID

                var certStatusTag = single.PeekTag();
                if (certStatusTag.TagClass == TagClass.ContextSpecific)
                {
                    switch (certStatusTag.TagValue)
                    {
                        case 0:
                            return true;  // good
                        case 1:
                            return false; // revoked
                        case 2:
                            throw new InvalidOperationException("OCSP response indicates certificate status is 'unknown'.");
                    }
                }
                break;
            }

            throw new InvalidDataException("OCSP response does not contain a valid certificate status.");
        }
        finally
        {
            responderCert?.Dispose();
        }
    }

    internal static bool VerifyOcspSignature(X509Certificate2 responderCert, byte[] tbsData, byte[] signature, string sigAlgOid, ILogger? logger = null)
    {
        try
        {
            using var rsa = responderCert.GetRSAPublicKey();
            if (rsa is not null)
            {
                var hashAlg = sigAlgOid switch
                {
                    Oids.RsaSha256 => HashAlgorithmName.SHA256,
                    Oids.RsaSha384 => HashAlgorithmName.SHA384,
                    Oids.RsaSha512 => HashAlgorithmName.SHA512,
                    Oids.RsaSha1 => HashAlgorithmName.SHA1,
                    Oids.RsaPss => HashAlgorithmName.SHA256,
                    _ => HashAlgorithmName.SHA256
                };
                var padding = sigAlgOid == Oids.RsaPss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
                return rsa.VerifyData(tbsData, signature, hashAlg, padding);
            }

            using var ecdsa = responderCert.GetECDsaPublicKey();
            if (ecdsa is not null)
            {
                var hashAlg = sigAlgOid switch
                {
                    Oids.EcdsaSha256 => HashAlgorithmName.SHA256,
                    Oids.EcdsaSha384 => HashAlgorithmName.SHA384,
                    Oids.EcdsaSha512 => HashAlgorithmName.SHA512,
                    _ => HashAlgorithmName.SHA256
                };
                return ecdsa.VerifyData(tbsData, signature, hashAlg);
            }

            logger?.OcspSignatureVerificationFailed($"Unsupported OCSP responder key type (not RSA/ECDSA). Cannot verify response signature.");
            return false;
        }
        catch (CryptographicException ex) { logger?.OcspSignatureVerificationFailed(ex.Message); return false; }
    }

    /// <summary>
    /// Extracts the OCSP server URL from the AIA (Authority Information Access) extension.
    /// AIA OID = 1.3.6.1.5.5.7.1.1
    ///   id-ad-ocsp      = 1.3.6.1.5.5.7.48.1
    ///   id-ad-caIssuers = 1.3.6.1.5.5.7.48.2
    /// </summary>
    internal static string? GetOcspUrl(X509Certificate2 cert)
    {
        var aia = cert.Extensions[Oids.AuthorityInfoAccess];
        if (aia is null)
        {
            return null;
        }

        return ParseAiaUri(aia.RawData, Oids.AdOcsp); // id-ad-ocsp
    }

    /// <summary>
    /// Extracts the first HTTP URL of the issuer (caIssuers) from the AIA extension.
    /// Used to download the issuer certificate when necessary.
    /// </summary>
    internal static string? GetCaIssuersUrl(X509Certificate2 cert)
    {
        var aia = cert.Extensions[Oids.AuthorityInfoAccess];
        if (aia is null)
        {
            return null;
        }

        return ParseAiaUri(aia.RawData, Oids.AdCaIssuers); // id-ad-caIssuers
    }

    internal static string? ParseAiaUri(byte[] rawAia, string targetOid, ILogger? logger = null)
    {
        try
        {
            var reader = new AsnReader(rawAia, AsnEncodingRules.DER);
            var seq = reader.ReadSequence();
            while (seq.HasData)
            {
                var accessDesc = seq.ReadSequence();
                string oid = accessDesc.ReadObjectIdentifier();
                // GeneralName [6] IA5String = uniformResourceIdentifier
                if (accessDesc.HasData)
                {
                    var gnTag = accessDesc.PeekTag();
                    if (gnTag.TagClass == TagClass.ContextSpecific && gnTag.TagValue == 6)
                    {
                        string uri = accessDesc.ReadCharacterString(
                            UniversalTagNumber.IA5String,
                            new Asn1Tag(TagClass.ContextSpecific, 6));
                        if (oid == targetOid)
                        {
                            return uri;
                        }
                    }
                    else
                    {
                        accessDesc.ReadEncodedValue(); // skips other GeneralName types
                    }
                }
            }
        }
        catch (AsnContentException ex) { logger?.OcspUrlExtensionParsingFailed(ex.Message); }
        return null;
    }
    #endregion

}
