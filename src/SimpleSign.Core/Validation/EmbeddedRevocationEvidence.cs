using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Revocation;

namespace SimpleSign.Core.Validation;

/// <summary>Checks whether embedded revocation evidence covers each supplied non-root certificate.</summary>
public static class EmbeddedRevocationEvidence
{
    /// <summary>
    /// Checks applicable, signed and current OCSP or CRL evidence for every non-self-signed
    /// certificate. This checks evidence integrity and coverage, not certificate-path trust.
    /// </summary>
    public static bool CoversAll(
        IReadOnlyList<X509Certificate2> certificates,
        IReadOnlyList<byte[]> ocspResponses,
        IReadOnlyList<byte[]> crls,
        DateTimeOffset validationTime,
        IOcspClient ocspClient) =>
        CoversAll(certificates, certificates, ocspResponses, crls, validationTime, ocspClient);

    /// <summary>Checks required certificates using issuer certificates available in the artifact.</summary>
    public static bool CoversAll(
        IReadOnlyList<X509Certificate2> requiredCertificates,
        IReadOnlyList<X509Certificate2> availableCertificates,
        IReadOnlyList<byte[]> ocspResponses,
        IReadOnlyList<byte[]> crls,
        DateTimeOffset validationTime,
        IOcspClient ocspClient)
    {
        ArgumentNullException.ThrowIfNull(requiredCertificates);
        ArgumentNullException.ThrowIfNull(availableCertificates);
        ArgumentNullException.ThrowIfNull(ocspResponses);
        ArgumentNullException.ThrowIfNull(crls);
        ArgumentNullException.ThrowIfNull(ocspClient);

        bool hasRequiredCertificate = false;
        var pending = new Queue<X509Certificate2>(requiredCertificates);
        foreach (var responder in availableCertificates.Where(IsOcspResponder))
        {
            pending.Enqueue(responder);
        }
        var checkedCertificates = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        while (pending.Count > 0)
        {
            var certificate = pending.Dequeue();
            if (!checkedCertificates.Add(certificate.Thumbprint))
            {
                continue;
            }

            if (!availableCertificates.Any(available => available.RawData.AsSpan().SequenceEqual(certificate.RawData)))
            {
                return false;
            }
            // A trust-anchor candidate and an OCSP responder with id-pkix-ocsp-nocheck
            // do not need a revocation object of their own.
            if (certificate.IsSelfSigned() && IsIssuedBy(certificate, certificate) ||
                IsNoCheckResponder(certificate))
            {
                continue;
            }

            hasRequiredCertificate = true;
            var issuer = availableCertificates.FindIssuerOf(certificate);
            if (issuer is null)
            {
                return false;
            }

            pending.Enqueue(issuer);

            // A matching distinguished name alone does not establish that this key
            // issued the subject certificate.
            if (!IsIssuedBy(certificate, issuer))
            {
                return false;
            }

            if (!CoversCertificate(certificate, issuer, ocspResponses, crls, validationTime, ocspClient))
            {
                return false;
            }
        }

        return hasRequiredCertificate;
    }

    private static bool IsNoCheckResponder(X509Certificate2 certificate)
    {
        if (certificate.Extensions[Oids.OcspNoCheck] is null)
        {
            return false;
        }

        return IsOcspResponder(certificate);
    }

    private static bool IsOcspResponder(X509Certificate2 certificate) =>
        certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>()
            .Any(extension => extension.EnhancedKeyUsages.Cast<Oid>()
                .Any(usage => usage.Value == "1.3.6.1.5.5.7.3.9"));

    internal static bool IsIssuedBy(X509Certificate2 certificate, X509Certificate2 issuer)
    {
        try
        {
            if (!certificate.IssuerName.RawData.AsSpan().SequenceEqual(issuer.SubjectName.RawData))
            {
                return false;
            }

            var reader = new AsnReader(certificate.RawData, AsnEncodingRules.BER);
            var sequence = reader.ReadSequence();
            byte[] tbs = sequence.ReadEncodedValue().ToArray();
            var algorithm = sequence.ReadSequence();
            string oid = algorithm.ReadObjectIdentifier();
            byte[]? parameters = algorithm.HasData ? algorithm.ReadEncodedValue().ToArray() : null;
            byte[] signature = sequence.ReadBitString(out _);

            if (oid is not (Oids.RsaSha1 or Oids.RsaSha256 or Oids.RsaSha384 or Oids.RsaSha512
                or Oids.EcdsaSha256 or Oids.EcdsaSha384 or Oids.EcdsaSha512 or Oids.RsaPss))
            {
                return false;
            }

            return OcspClient.VerifyOcspSignature(issuer, tbs, signature, oid, parameters);
        }
        catch (Exception ex) when (ex is AsnContentException or CryptographicException or InvalidOperationException)
        {
            return false;
        }
    }

    /// <summary>Checks embedded evidence for one certificate using its known issuer.</summary>
    public static bool CoversCertificate(
        X509Certificate2 certificate,
        X509Certificate2 issuer,
        IReadOnlyList<byte[]> ocspResponses,
        IReadOnlyList<byte[]> crls,
        DateTimeOffset validationTime,
        IOcspClient ocspClient)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(ocspResponses);
        ArgumentNullException.ThrowIfNull(crls);
        ArgumentNullException.ThrowIfNull(ocspClient);

        bool covered = false;
        foreach (var response in ocspResponses)
        {
            try
            {
                bool? status = ocspClient.CheckEmbeddedOcspResponse(
                    certificate, issuer, response, validationTime);
                if (status == false)
                {
                    return false;
                }

                if (status == true)
                {
                    covered = true;
                }
            }
            catch (Exception ex) when (ex is AsnContentException or CryptographicException or InvalidDataException or InvalidOperationException)
            {
                // An unrelated or invalid response cannot cover this certificate.
            }
        }

        foreach (var crl in crls)
        {
            try
            {
                if (!HasBoundedCrlInterval(crl, validationTime))
                {
                    continue;
                }

                bool? isRevoked = CrlClient.IsSerialInCrl(
                    certificate, crl, issuer, signingTime: validationTime);
                if (isRevoked == true)
                {
                    return false;
                }

                if (isRevoked == false)
                {
                    covered = true;
                }
            }
            catch (CryptographicException)
            {
                // Invalid CRL signature or issuer key.
            }
        }

        return covered;
    }

    private static bool HasBoundedCrlInterval(byte[] crl, DateTimeOffset validationTime)
    {
        try
        {
            var reader = new AsnReader(crl, AsnEncodingRules.BER);
            var certificateList = reader.ReadSequence();
            var tbs = certificateList.ReadSequence();
            if (tbs.HasData && tbs.PeekTag().HasSameClassAndValue(Asn1Tag.Integer))
            {
                _ = tbs.ReadInteger();
            }

            _ = tbs.ReadEncodedValue(); // signature algorithm
            _ = tbs.ReadEncodedValue(); // issuer
            var thisUpdate = ReadCrlTime(tbs);
            var nextUpdate = ReadCrlTime(tbs);
            return thisUpdate <= validationTime && validationTime <= nextUpdate;
        }
        catch (AsnContentException)
        {
            return false;
        }
    }

    private static DateTimeOffset ReadCrlTime(AsnReader reader)
    {
        var tag = reader.PeekTag();
        return tag.TagValue == (int)UniversalTagNumber.UtcTime
            ? reader.ReadUtcTime()
            : reader.ReadGeneralizedTime();
    }
}
