using SimpleSign.Brasil.IcpBrasil;
using SimpleSign.CAdES;
using SimpleSign.Core.Signing;

namespace SimpleSign.Brasil.Signing;

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
        if (policy != IcpBrasilPolicy.AdRb && timestamp is null)
        {
            throw new ArgumentException($"{policy} requires a timestamp authority (an ICP-Brasil ACT).", nameof(timestamp));
        }

        var root = builder.SignerCertificate is { } signer
            ? IcpBrasilChainValidator.FindBundledRoot(signer, builder.SignerChain)
            : null;
        var current = root is null
            ? IcpBrasilSignaturePolicies.Current(policy, IcpBrasilPolicyFormat.Cades)
            : IcpBrasilSignaturePolicies.Current(policy, IcpBrasilPolicyFormat.Cades, root);

        builder = builder.WithSignaturePolicy(current.ToReference());
        if (timestamp is not null)
        {
            builder = builder.WithLevel(AdesBaselineProfile.Timestamped(timestamp));
        }

        return builder.WithExtendedValidationData(policy switch
        {
            IcpBrasilPolicy.AdRv => CadesExtendedForm.CompleteReferences,
            IcpBrasilPolicy.AdRc => CadesExtendedForm.ExtendedLong,
            IcpBrasilPolicy.AdRa => CadesExtendedForm.Archive,
            _ => CadesExtendedForm.None,
        });
    }
}
