using System.Formats.Asn1;
using System.Security.Cryptography;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Validation;

namespace SimpleSign.Brasil.IcpBrasil;

/// <summary>One entry of an ITI policy list (LPA, DOC-ICP-15.03): a policy and the digest of its PA file.</summary>
/// <param name="Oid">The policy OID.</param>
/// <param name="Uri">The URI of the PA file.</param>
/// <param name="DigestAlgorithmOid">The algorithm of <paramref name="Digest"/>.</param>
/// <param name="Digest">The digest of the whole PA file.</param>
/// <param name="NotBefore">Start of the signing period.</param>
/// <param name="NotAfter">End of the signing period.</param>
/// <param name="RevokedAt">When the ITI revoked the policy, if it did.</param>
public sealed record IcpBrasilLpaEntry(
    string Oid, string Uri, string DigestAlgorithmOid, ReadOnlyMemory<byte> Digest,
    DateTimeOffset NotBefore, DateTimeOffset NotAfter, DateTimeOffset? RevokedAt);

/// <summary>A parsed ITI policy list (LPA_PAdES.der, LPA_CAdES.der).</summary>
/// <param name="Entries">The policies listed.</param>
/// <param name="NextUpdate">When the ITI will publish the next LPA.</param>
public sealed record IcpBrasilLpa(IReadOnlyList<IcpBrasilLpaEntry> Entries, DateTimeOffset NextUpdate)
{
    /// <summary>Parses a DER-encoded LPA.</summary>
    /// <param name="lpa">The LPA bytes.</param>
    /// <exception cref="ArgumentException">The bytes are not an LPA.</exception>
    public static IcpBrasilLpa Parse(ReadOnlySpan<byte> lpa)
    {
        try
        {
            // LPA ::= SEQUENCE { policyInfos SEQUENCE OF PolicyInfo, nextUpdate GeneralizedTime }
            // PolicyInfo ::= SEQUENCE { signingPeriod SEQUENCE { notBefore, notAfter OPTIONAL },
            //   revocationDate GeneralizedTime OPTIONAL, policyOID, policyURI IA5String,
            //   policyDigest SEQUENCE { AlgorithmIdentifier, OCTET STRING } }
            var root = new AsnReader(lpa.ToArray(), AsnEncodingRules.DER).ReadSequence();
            var infos = root.ReadSequence();
            var entries = new List<IcpBrasilLpaEntry>();
            while (infos.HasData)
            {
                var info = infos.ReadSequence();
                var period = info.ReadSequence();
                DateTimeOffset notBefore = period.ReadGeneralizedTime();
                DateTimeOffset notAfter = period.HasData ? period.ReadGeneralizedTime() : DateTimeOffset.MaxValue;
                DateTimeOffset? revoked = info.PeekTag() == Asn1Tag.GeneralizedTime ? info.ReadGeneralizedTime() : null;
                string oid = info.ReadObjectIdentifier();
                string uri = info.ReadCharacterString(UniversalTagNumber.IA5String);
                var digest = info.ReadSequence();
                string alg = digest.ReadSequence().ReadObjectIdentifier();
                byte[] value = digest.ReadOctetString();
                entries.Add(new IcpBrasilLpaEntry(oid, uri, alg, value, notBefore, notAfter, revoked));
            }

            return new IcpBrasilLpa(entries.AsReadOnly(), root.ReadGeneralizedTime());
        }
        catch (AsnContentException ex)
        {
            throw new ArgumentException("The bytes are not a DER-encoded ICP-Brasil LPA.", nameof(lpa), ex);
        }
    }
}

public static partial class IcpBrasilSignaturePolicies
{
    /// <summary>The ITI repository of signature policies and LPAs.</summary>
    public static readonly Uri Repository = new("https://politicas.icpbrasil.gov.br/");

    // CNPJ of the ITI (Instituto Nacional de Tecnologia da Informação), the LPA signer.
    private const string ItiCnpj = "04039532000193";

    /// <summary>
    /// Downloads the current LPA of <paramref name="format"/> from the ITI and updates
    /// <see cref="All"/>, <see cref="TryFind"/> and <see cref="Current(IcpBrasilPolicy, IcpBrasilPolicyFormat, DateTimeOffset?)"/>:
    /// <list type="number">
    /// <item>the LPA's detached signature (<c>LPA_*.p7s</c>) must verify, be made by the ITI and chain to an ICP-Brasil AC Raiz (not revoked);</item>
    /// <item>known policies take the LPA's signing period and revocation date (revocations are published this way);</item>
    /// <item>new policies are downloaded, accepted only if the PA file matches the digest in the LPA, and parsed.</item>
    /// </list>
    /// Call it at start-up or when <see cref="IcpBrasilLpa.NextUpdate"/> has passed; on failure the current catalog is kept.
    /// </summary>
    /// <param name="httpClient">HTTP client for the ITI repository, LCRs and AIA.</param>
    /// <param name="format">PAdES or CAdES (XAdES is not supported).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The LPA that was applied.</returns>
    /// <exception cref="CryptographicException">The LPA signature or a PA digest does not verify.</exception>
    /// <exception cref="HttpRequestException">A download failed.</exception>
    public static Task<IcpBrasilLpa> RefreshAsync(
        HttpClient httpClient, IcpBrasilPolicyFormat format, CancellationToken cancellationToken = default) =>
        RefreshAsync(httpClient, format, chainValidator: null, cancellationToken);

    /// <summary>Test seam: <paramref name="chainValidator"/> validates the LPA signer (default: bundled roots).</summary>
    internal static async Task<IcpBrasilLpa> RefreshAsync(
        HttpClient httpClient, IcpBrasilPolicyFormat format, IcpBrasilChainValidator? chainValidator, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        string name = format switch
        {
            IcpBrasilPolicyFormat.Pades => "LPA_PAdES",
            IcpBrasilPolicyFormat.Cades => "LPA_CAdES",
            _ => throw new ArgumentException("Only the PAdES and CAdES LPAs are supported.", nameof(format)),
        };

        byte[] lpaBytes = await DownloadAsync(httpClient, new Uri(Repository, name + ".der"), cancellationToken).ConfigureAwait(false);
        byte[] signature = await DownloadAsync(httpClient, new Uri(Repository, name + ".p7s"), cancellationToken).ConfigureAwait(false);
        await VerifyLpaSignatureAsync(lpaBytes, signature, httpClient, cancellationToken, chainValidator).ConfigureAwait(false);

        var lpa = IcpBrasilLpa.Parse(lpaBytes);
        var updated = new List<IcpBrasilSignaturePolicy>();
        var newRules = new List<IcpBrasilPolicyRules>();
        foreach (var entry in lpa.Entries)
        {
            if (TryFind(entry.Oid, out var known))
            {
                updated.Add(known with { NotBefore = entry.NotBefore, NotAfter = entry.NotAfter, RevokedAt = entry.RevokedAt });
                continue;
            }

            var paUri = ToHttps(new Uri(entry.Uri));
            byte[] pa = await DownloadAsync(httpClient, paUri, cancellationToken).ConfigureAwait(false);
            if (!CryptographicOperations.FixedTimeEquals(HashData(entry.DigestAlgorithmOid, pa), entry.Digest.Span))
            {
                throw new CryptographicException($"The PA at {entry.Uri} does not match the digest listed in {name}.");
            }

            newRules.Add(IcpBrasilPolicyRules.Parse(pa));
            updated.Add(FromPolicyDocument(pa, entry.Uri) with
            {
                NotBefore = entry.NotBefore,
                NotAfter = entry.NotAfter,
                RevokedAt = entry.RevokedAt,
            });
        }

        Apply(updated);
        ApplyRules(newRules);
        return lpa;
    }

    /// <summary>
    /// Verifies an LPA's detached CMS signature: message digest, signature value, an ITI
    /// certificate (CNPJ 04.039.532/0001-93) that chains to an ICP-Brasil AC Raiz and is not revoked.
    /// </summary>
    internal static async Task VerifyLpaSignatureAsync(
        byte[] lpa, byte[] signature, HttpClient httpClient, CancellationToken cancellationToken,
        IcpBrasilChainValidator? chainValidator = null)
    {
        CmsSignedData cms;
        try
        {
            cms = CmsParser.Parse(signature);
        }
        catch (AsnContentException ex)
        {
            throw new CryptographicException("The LPA signature is not a CMS SignedData.", ex);
        }

        if (cms.SignerCertificate is null || cms.MessageDigest is null
            || !CryptographicOperations.FixedTimeEquals(HashData(cms.DigestAlgorithmOid, lpa), cms.MessageDigest)
            || !CryptoVerifier.VerifySignature(cms))
        {
            throw new CryptographicException("The LPA signature does not verify.");
        }

        var (_, cnpj) = IcpBrasilChainValidator.ExtractCpfCnpj(cms.SignerCertificate);
        if (cnpj != ItiCnpj)
        {
            throw new CryptographicException("The LPA is not signed by the ITI.");
        }

        var validator = chainValidator ?? new IcpBrasilChainValidator(httpClient);
        var chain = await validator.ValidateAsync(new ChainValidationContext
        {
            Certificate = cms.SignerCertificate,
            Certificates = cms.Certificates,
            ValidationTime = cms.SigningTime,
            CheckRevocation = true,
        }, cancellationToken).ConfigureAwait(false);
        if (!chain.IsChainValid || chain.RevocationStatus == ChainRevocationStatus.Revoked)
        {
            throw new CryptographicException($"The LPA signer certificate is not trusted: {string.Join("; ", chain.Errors)}");
        }
    }

    private static async Task<byte[]> DownloadAsync(HttpClient httpClient, Uri uri, CancellationToken cancellationToken) =>
        await ResilientHttp.GetBytesAsync(httpClient, uri.AbsoluteUri, ct: cancellationToken).ConfigureAwait(false)
            ?? throw new HttpRequestException($"Could not download {uri}.");

    private static Uri ToHttps(Uri uri) =>
        uri.Scheme == Uri.UriSchemeHttp && uri.Host.EndsWith("icpbrasil.gov.br", StringComparison.OrdinalIgnoreCase)
            ? new UriBuilder(uri) { Scheme = Uri.UriSchemeHttps, Port = -1 }.Uri
            : uri;

#pragma warning disable CA5350 // SHA-1 digests appear in old ICP-Brasil LPA entries and signatures
    private static byte[] HashData(string algorithmOid, byte[] data) => algorithmOid switch
    {
        Oids.Sha256 => SHA256.HashData(data),
        Oids.Sha384 => SHA384.HashData(data),
        Oids.Sha512 => SHA512.HashData(data),
        Oids.Sha1 => SHA1.HashData(data),
        _ => throw new CryptographicException($"Digest algorithm {algorithmOid} is not supported."),
    };
#pragma warning restore CA5350
}
