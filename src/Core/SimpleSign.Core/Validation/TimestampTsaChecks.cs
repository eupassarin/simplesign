using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Signing;

namespace SimpleSign.Core.Validation;

/// <summary>
/// The checks on the time-stamping authority of an RFC 3161 token beyond its signature: the TSA name
/// carried in TSTInfo (RFC 3161 §2.4.2) and the revocation of the TSA certificate chain at genTime.
/// </summary>
public static class TimestampTsaChecks
{
    /// <summary>
    /// Whether the <c>tsa</c> field of TSTInfo names the TSA certificate: its subject for a directoryName,
    /// otherwise one of its subject alternative names. Null when the token has no <c>tsa</c> field.
    /// </summary>
    /// <param name="timestampToken">DER-encoded RFC 3161 token.</param>
    /// <param name="tsaCertificate">The certificate that signed the token.</param>
    /// <returns><see langword="true"/> when the name matches, <see langword="false"/> when it does not, null when absent or unreadable.</returns>
    public static bool? TsaNameMatches(byte[] timestampToken, X509Certificate2 tsaCertificate)
    {
        ArgumentNullException.ThrowIfNull(timestampToken);
        ArgumentNullException.ThrowIfNull(tsaCertificate);
        byte[]? generalName = ReadTsaGeneralName(timestampToken);
        if (generalName is null)
        {
            return null;
        }

        var reader = new AsnReader(generalName, AsnEncodingRules.BER);
        var tag = reader.PeekTag();
        if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 4)))
        {
            byte[] name = reader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 4, true)).ReadEncodedValue().ToArray();
            if (name.AsSpan().SequenceEqual(tsaCertificate.SubjectName.RawData)
                || string.Equals(new X500DistinguishedName(name).Name, tsaCertificate.SubjectName.Name, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return SubjectAlternativeNames(tsaCertificate).Any(san => san.AsSpan().SequenceEqual(generalName));
    }

    /// <summary>
    /// Whether the <c>tsa</c> field of TSTInfo names the certificate that signed the token (the first certificate
    /// the token carries for its signer). Null when the token has no <c>tsa</c> field or carries no certificate.
    /// </summary>
    /// <param name="timestampToken">DER-encoded RFC 3161 token.</param>
    /// <returns><see langword="true"/> when the name matches, <see langword="false"/> when it does not, null when it cannot be told.</returns>
    public static bool? TsaNameMatches(byte[] timestampToken)
    {
        ArgumentNullException.ThrowIfNull(timestampToken);
        return TimestampValidator.ReadTokenCertificates(timestampToken) is [var tsa, ..] ? TsaNameMatches(timestampToken, tsa) : null;
    }

    /// <summary>
    /// Checks the revocation of the TSA certificate chain at the token's genTime. The chain is built from
    /// the token's certificates and <paramref name="extraCertificates"/> (trust anchors, embedded
    /// certificates). Returns <paramref name="result"/> unchanged when the TSA is not trusted already, or
    /// when no certificate of the chain publishes revocation information and none is embedded; otherwise
    /// a revoked or unknown status makes the TSA untrusted, with the reasons in <paramref name="warnings"/>.
    /// </summary>
    /// <param name="result">The integrity and trust outcome of the token.</param>
    /// <param name="timestampToken">DER-encoded RFC 3161 token.</param>
    /// <param name="extraCertificates">Certificates that may complete the TSA chain.</param>
    /// <param name="checker">The chain revocation checker.</param>
    /// <param name="embeddedCrls">CRLs embedded with the signature.</param>
    /// <param name="embeddedOcsps">OCSP responses embedded with the signature.</param>
    /// <param name="allowOnline">Whether CRL distribution points and OCSP responders may be queried.</param>
    /// <param name="warnings">Receives the reasons the TSA became untrusted.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The outcome, with <see cref="TimestampTokenValidationResult.IsTsaTrusted"/> updated.</returns>
    public static async Task<TimestampTokenValidationResult> CheckTsaRevocationAsync(
        TimestampTokenValidationResult result,
        byte[] timestampToken,
        IReadOnlyList<X509Certificate2> extraCertificates,
        IChainRevocationChecker checker,
        IReadOnlyList<byte[]> embeddedCrls,
        IReadOnlyList<byte[]> embeddedOcsps,
        bool allowOnline,
        List<string> warnings,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(timestampToken);
        ArgumentNullException.ThrowIfNull(extraCertificates);
        ArgumentNullException.ThrowIfNull(checker);
        ArgumentNullException.ThrowIfNull(embeddedCrls);
        ArgumentNullException.ThrowIfNull(embeddedOcsps);
        ArgumentNullException.ThrowIfNull(warnings);
        if (result.IsTsaTrusted != true || result.GenTime is not { } genTime)
        {
            return result;
        }

        var tokenCertificates = TimestampValidator.ReadTokenCertificates(timestampToken);
        if (tokenCertificates.Count == 0)
        {
            return result;
        }

        var ordered = SignerAcceptance.OrderChain(tokenCertificates[0], [.. tokenCertificates.Skip(1), .. extraCertificates]);
        bool publishesRevocation = ordered.Take(Math.Max(1, ordered.Count - 1))
            .Any(c => c.Extensions[Oids.CrlDistributionPoints] is not null || c.Extensions[Oids.AuthorityInfoAccess] is not null);
        if (!publishesRevocation && embeddedCrls.Count == 0 && embeddedOcsps.Count == 0)
        {
            warnings.Add("TSA: the TSA certificate chain publishes no revocation information; its revocation was not checked.");
            return result;
        }

        var last = ordered[^1];
        if (!last.SubjectName.RawData.AsSpan().SequenceEqual(last.IssuerName.RawData))
        {
            warnings.Add($"TSA: the issuer of '{last.Subject}' is unknown, so the revocation of the TSA chain cannot be established.");
            return Untrusted(result);
        }

        var revocation = await checker.CheckAsync(ordered, genTime, embeddedCrls, embeddedOcsps, allowOnline, cancellationToken)
            .ConfigureAwait(false);
        if (revocation.Status == ChainRevocationStatus.Good)
        {
            return result;
        }

        warnings.AddRange(revocation.Messages.Select(m => "TSA: " + m));
        warnings.Add(revocation.Status == ChainRevocationStatus.Revoked
            ? "TSA: the TSA certificate chain is revoked at the time of the timestamp."
            : "TSA: the revocation status of the TSA certificate chain could not be established.");
        return Untrusted(result);
    }

    private static TimestampTokenValidationResult Untrusted(TimestampTokenValidationResult result) => new()
    {
        IsIntegrityValid = result.IsIntegrityValid,
        IsTsaTrusted = false,
        GenTime = result.GenTime,
    };

    /// <summary>The encoded <c>[0] GeneralName</c> content of TSTInfo's <c>tsa</c> field, or null.</summary>
    private static byte[]? ReadTsaGeneralName(byte[] timestampToken)
    {
        try
        {
            byte[]? tstInfoBytes = TimestampValidator.ExtractTstInfoBytes(timestampToken);
            if (tstInfoBytes is null)
            {
                return null;
            }

            var tstInfo = new AsnReader(tstInfoBytes, AsnEncodingRules.BER).ReadSequence();
            _ = tstInfo.ReadInteger();
            _ = tstInfo.ReadObjectIdentifier();
            _ = tstInfo.ReadSequence();
            _ = tstInfo.ReadInteger();
            _ = tstInfo.ReadGeneralizedTime();
            while (tstInfo.HasData)
            {
                var tag = tstInfo.PeekTag();
                if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    return tstInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)).ReadEncodedValue().ToArray();
                }

                tstInfo.ReadEncodedValue();
            }

            return null;
        }
        catch (Exception ex) when (ex is AsnContentException or CryptographicException)
        {
            return null;
        }
    }

    private static IEnumerable<byte[]> SubjectAlternativeNames(X509Certificate2 certificate)
    {
        var san = certificate.Extensions["2.5.29.17"];
        if (san is null)
        {
            yield break;
        }

        var names = new List<byte[]>();
        try
        {
            var sequence = new AsnReader(san.RawData, AsnEncodingRules.BER).ReadSequence();
            while (sequence.HasData)
            {
                names.Add(sequence.ReadEncodedValue().ToArray());
            }
        }
        catch (AsnContentException)
        {
            // An unreadable extension matches nothing.
        }

        foreach (var name in names)
        {
            yield return name;
        }
    }
}
