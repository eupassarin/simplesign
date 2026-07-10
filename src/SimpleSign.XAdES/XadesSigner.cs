using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;

namespace SimpleSign.XAdES;

/// <summary>
/// Creates XAdES digital signatures (ETSI EN 319 132) for XML documents.
/// Supports enveloped, detached, and enveloping XML signatures.
/// </summary>
[RequiresUnreferencedCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
[RequiresDynamicCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
public static class XadesSigner
{
    /// <summary>Creates a new fluent builder for signing XML data with XAdES.</summary>
    public static XadesSignerBuilder Document(byte[] xmlData, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(xmlData);
        return new XadesSignerBuilder(xmlData, logger);
    }

    /// <summary>Signs the provided XML data and returns a XAdES envelope signature.</summary>
    public static async Task<byte[]> SignAsync(
        byte[] data,
        X509Certificate2 certificate,
        XadesSigningOptions? options = null,
        ILogger? logger = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(certificate);
        if (!certificate.HasPrivateKey)
        {
            throw new ArgumentException("Certificate must have a private key.", nameof(certificate));
        }

        options ??= new XadesSigningOptions();

        var builder = Document(data, logger)
            .WithCertificate(certificate)
            .WithHashAlgorithm(options.HashAlgorithm)
            .WithLevel(options.Level)
            .WithForm(options.Form);

        if (options.DataUri is not null)
        {
            builder = builder.WithDataUri(options.DataUri);
        }

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

        if (options.SignerRoles is not null && options.SignerRoles.Count > 0)
        {
            builder = builder.WithSignerRoles(options.SignerRoles);
        }

        if (options.DataObjectFormat is not null)
        {
            builder = builder.WithDataObjectFormat(options.DataObjectFormat);
        }

        return await builder.SignAsync(cancellationToken).ConfigureAwait(false);
    }
}
