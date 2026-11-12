using SimpleSign.CAdES;
using SimpleSign.Core.Signing;

namespace SimpleSign.Brazil.IcpBrasil;

/// <summary>Signs CAdES (.p7s) under ICP-Brasil signature policies.</summary>
public static class IcpBrasilCadesExtensions
{
    /// <summary>
    /// Signs under an ICP-Brasil CAdES policy: the newest version that accepts the signer's root, with
    /// its sigPolicyHash, and the attributes the PA mandates — AD-RT: signature timestamp; AD-RV:
    /// + complete references and escTimeStamp; AD-RC: + certificate and revocation values;
    /// AD-RA: references, values and an archive-time-stamp v2. Every level above AD-RB needs a TSA
    /// (an ICP-Brasil ACT) and, from AD-RV, the LCR/OCSP of the whole path.
    /// Call after <c>WithCertificate</c> / <c>WithExternalSigner</c>.
    /// </summary>
    /// <param name="builder">The CAdES builder.</param>
    /// <param name="policy">AD-RB, AD-RT, AD-RV, AD-RC or AD-RA.</param>
    /// <param name="timestamp">The TSA; required above AD-RB.</param>
    /// <exception cref="ArgumentException">A policy above AD-RB without a TSA.</exception>
    /// <exception cref="IcpBrasilPolicyException">No version of the policy accepts the signer's root.</exception>
    /// <example>
    /// <code>
    /// byte[] p7s = await CadesSigner.Document(data).WithCertificate(cert)
    ///     .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRc, new TimestampOptions(new Uri(actUrl)))
    ///     .SignAsync();
    /// </code>
    /// </example>
    public static CadesSignerBuilder WithIcpBrasilPolicy(
        this CadesSignerBuilder builder, IcpBrasilPolicy policy = IcpBrasilPolicy.AdRb, TimestampOptions? timestamp = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        IcpBrasilSignaturePolicy current = Version(builder.SignerCertificate, builder.SignerChain, policy, timestamp);
        builder = builder.WithSignaturePolicy(current.ToReference());
        if (timestamp is not null)
        {
            builder = builder.WithLevel(AdesBaselineProfile.Timestamped(timestamp));
        }

        return builder.WithExtendedValidationData(ExtendedForm(policy));
    }

    /// <summary>
    /// Prepares a two-phase signature under an ICP-Brasil CAdES policy: the same policy version, sigPolicyHash
    /// and attributes as <see cref="WithIcpBrasilPolicy(CadesSignerBuilder, IcpBrasilPolicy, TimestampOptions)"/>.
    /// The policy identifier is fixed when the signature is prepared; the timestamp and the extended form are
    /// added when the session is completed. Call after <c>WithCertificate</c>.
    /// </summary>
    /// <param name="builder">The deferred CAdES builder, before <c>PrepareAsync</c>.</param>
    /// <param name="policy">AD-RB, AD-RT, AD-RV, AD-RC or AD-RA.</param>
    /// <param name="timestamp">The TSA; required above AD-RB.</param>
    /// <exception cref="ArgumentException">A policy above AD-RB without a TSA.</exception>
    /// <exception cref="IcpBrasilPolicyException">No version of the policy accepts the signer's root.</exception>
    public static CadesDeferredSignerBuilder WithIcpBrasilPolicy(
        this CadesDeferredSignerBuilder builder, IcpBrasilPolicy policy = IcpBrasilPolicy.AdRb, TimestampOptions? timestamp = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        IcpBrasilSignaturePolicy current = Version(builder.SignerCertificate, builder.SignerChain, policy, timestamp);
        builder = builder.WithSignaturePolicy(current.ToReference());
        if (timestamp is not null)
        {
            builder = builder.WithLevel(AdesBaselineProfile.Timestamped(timestamp));
        }

        return builder.WithExtendedValidationData(ExtendedForm(policy));
    }

    private static IcpBrasilSignaturePolicy Version(
        System.Security.Cryptography.X509Certificates.X509Certificate2? signer,
        IReadOnlyList<System.Security.Cryptography.X509Certificates.X509Certificate2> chain,
        IcpBrasilPolicy policy,
        TimestampOptions? timestamp)
    {
        if (policy != IcpBrasilPolicy.AdRb && timestamp is null)
        {
            throw new ArgumentException($"{policy} requires a timestamp authority (an ICP-Brasil ACT).", nameof(timestamp));
        }

        var root = signer is null ? null : IcpBrasilChainValidator.FindBundledRoot(signer, chain);
        return root is null
            ? IcpBrasilSignaturePolicies.Current(policy, IcpBrasilPolicyFormat.Cades)
            : IcpBrasilSignaturePolicies.Current(policy, IcpBrasilPolicyFormat.Cades, root);
    }

    private static CadesExtendedForm ExtendedForm(IcpBrasilPolicy policy) => policy switch
    {
        IcpBrasilPolicy.AdRv => CadesExtendedForm.CompleteReferences,
        IcpBrasilPolicy.AdRc => CadesExtendedForm.ExtendedLong,
        IcpBrasilPolicy.AdRa => CadesExtendedForm.Archive,
        _ => CadesExtendedForm.None,
    };
}
