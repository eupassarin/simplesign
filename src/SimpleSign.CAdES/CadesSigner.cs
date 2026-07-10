using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;

namespace SimpleSign.CAdES;

/// <summary>
/// Creates standalone CAdES digital signatures (ETSI EN 319 122) as detached
/// CMS/PKCS#7 SignedData — no PDF wrapper.
/// </summary>
public static class CadesSigner
{
    /// <summary>
    /// Creates a new fluent builder for signing data with CAdES.
    /// </summary>
    /// <param name="data">The original document bytes to sign.</param>
    /// <param name="logger">Optional logger.</param>
    /// <returns>A <see cref="CadesSignerBuilder"/> configured with defaults.</returns>
    public static CadesSignerBuilder Document(byte[] data, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(data);
        return new CadesSignerBuilder(data, logger);
    }

    /// <summary>
    /// Signs the provided data and returns a DER-encoded CAdES signature.
    /// </summary>
    /// <param name="data">The original document bytes to sign.</param>
    /// <param name="certificate">Certificate with private key.</param>
    /// <param name="options">Optional signing configuration.</param>
    /// <param name="logger">Optional logger.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>DER-encoded CMS/PKCS#7 SignedData (detached).</returns>
    public static async Task<byte[]> SignAsync(
        byte[] data,
        X509Certificate2 certificate,
        CadesSigningOptions? options = null,
        ILogger? logger = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(certificate);

        if (!certificate.HasPrivateKey)
        {
            throw new ArgumentException("Certificate must have a private key.", nameof(certificate));
        }

        options ??= new CadesSigningOptions();

        var builder = Document(data, logger)
            .WithCertificate(certificate)
            .WithHashAlgorithm(options.HashAlgorithm)
            .WithLevel(options.Level)
            .WithContentType(options.ContentType);

        if (options.SignatureAlgorithmOid is not null)
        {
            builder = builder.WithSignatureAlgorithm(options.SignatureAlgorithmOid);
        }
        if (options.SigningTime.HasValue)
        {
            builder = builder.WithSigningTime(options.SigningTime.Value);
        }
        if (options.ExtraCertificates is not null)
        {
            builder = builder.WithCertificate(certificate, options.ExtraCertificates);
        }
        if (options.TsaUrl is not null)
        {
            builder = options.TsaHttpClient is not null
                ? builder.WithTimestamp(options.TsaUrl, options.TsaHttpClient)
                : builder.WithTimestamp(options.TsaUrl);
        }
        if (options.RevocationHttpClient is not null)
        {
            builder = builder.WithRevocationHttpClient(options.RevocationHttpClient);
        }
        if (options.CommitmentType.HasValue)
        {
            builder = builder.WithCommitmentType(options.CommitmentType.Value);
        }
        if (options.SignaturePolicyOid is not null)
        {
            builder = builder.WithSignaturePolicy(options.SignaturePolicyOid, options.SignaturePolicyUri);
        }

        return await builder.SignAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Signs the provided data using an external signing delegate.
    /// Use for HSMs, cloud KMS, or A3 tokens where the private key is not directly accessible.
    /// </summary>
    /// <param name="data">The original document bytes to sign.</param>
    /// <param name="certificate">The signer's public certificate (private key NOT required).</param>
    /// <param name="externalSigner">Delegate that receives signed attributes and returns raw signature bytes.</param>
    /// <param name="signatureAlgorithmOid">OID of the signature algorithm used by the external signer.</param>
    /// <param name="options">Optional signing configuration.</param>
    /// <param name="logger">Optional logger.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>DER-encoded CMS/PKCS#7 SignedData (detached).</returns>
    public static async Task<byte[]> SignAsync(
        byte[] data,
        X509Certificate2 certificate,
        Func<byte[], Task<byte[]>> externalSigner,
        string signatureAlgorithmOid,
        CadesSigningOptions? options = null,
        ILogger? logger = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(externalSigner);
        ArgumentException.ThrowIfNullOrWhiteSpace(signatureAlgorithmOid);

        options ??= new CadesSigningOptions();

        var builder = Document(data, logger)
            .WithExternalSigner(certificate, externalSigner, signatureAlgorithmOid)
            .WithHashAlgorithm(options.HashAlgorithm)
            .WithLevel(options.Level)
            .WithContentType(options.ContentType);

        if (options.SigningTime.HasValue)
        {
            builder = builder.WithSigningTime(options.SigningTime.Value);
        }
        if (options.ExtraCertificates is not null)
        {
            builder = builder.WithCertificate(certificate, options.ExtraCertificates);
        }
        if (options.TsaUrl is not null)
        {
            builder = options.TsaHttpClient is not null
                ? builder.WithTimestamp(options.TsaUrl, options.TsaHttpClient)
                : builder.WithTimestamp(options.TsaUrl);
        }
        if (options.RevocationHttpClient is not null)
        {
            builder = builder.WithRevocationHttpClient(options.RevocationHttpClient);
        }
        if (options.CommitmentType.HasValue)
        {
            builder = builder.WithCommitmentType(options.CommitmentType.Value);
        }
        if (options.SignaturePolicyOid is not null)
        {
            builder = builder.WithSignaturePolicy(options.SignaturePolicyOid, options.SignaturePolicyUri);
        }

        return await builder.SignAsync(cancellationToken).ConfigureAwait(false);
    }
}

