using SimpleSign.Brasil.IcpBrasil;
using SimpleSign.Brasil.Signing;
using SimpleSign.Core.Signing;
using SimpleSign.XAdES;

namespace SimpleSign.Brasil.Xades;

/// <summary>Signs XAdES under the ICP-Brasil XML signature policies.</summary>
public static class IcpBrasilXadesExtensions
{
    /// <summary>
    /// Signs under an ICP-Brasil XAdES policy: picks the newest version that accepts the signer's
    /// AC Raiz (call after <c>WithCertificate</c> / <c>WithExternalSigner</c>), writes
    /// SigningCertificate (XAdES 1.3.2) and the SignaturePolicyIdentifier with the PA's
    /// SignPolicyDigest, and adds what the policy mandates:
    /// AD-RT a SignatureTimeStamp; AD-RV the complete references and a SigAndRefsTimeStamp;
    /// AD-RC also the certificate and revocation values; AD-RA references, values and an
    /// ArchiveTimeStamp. Above AD-RB a TSA (an ICP-Brasil ACT) is required, and from AD-RV the
    /// LCR or OCSP response of every certificate in the path must be obtainable.
    /// </summary>
    /// <param name="builder">The XAdES builder.</param>
    /// <param name="policy">The policy (default AD-RB).</param>
    /// <param name="timestamp">The TSA, required above AD-RB.</param>
    /// <exception cref="ArgumentException">A policy above AD-RB without a TSA.</exception>
    /// <exception cref="IcpBrasilPolicyException">No version of the policy accepts the signer's root.</exception>
    /// <example>
    /// <code>
    /// await XadesSigner.Document(xml).WithCertificate(cert)
    ///     .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRt, new TimestampOptions(new Uri(actUrl)))
    ///     .SignAsync();
    /// </code>
    /// </example>
    public static XadesSignerBuilder WithIcpBrasilPolicy(
        this XadesSignerBuilder builder, IcpBrasilPolicy policy = IcpBrasilPolicy.AdRb, TimestampOptions? timestamp = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        if (policy != IcpBrasilPolicy.AdRb && timestamp is null)
        {
            throw new ArgumentException($"{policy} requires a signature timestamp: pass the TSA (an ICP-Brasil ACT).", nameof(timestamp));
        }

        var root = builder.SignerCertificate is { } signer
            ? IcpBrasilChainValidator.FindBundledRoot(signer, builder.SignerChain)
            : null;
        var current = root is null
            ? IcpBrasilSignaturePolicies.Current(policy, IcpBrasilPolicyFormat.Xades)
            : IcpBrasilSignaturePolicies.Current(policy, IcpBrasilPolicyFormat.Xades, root);
        builder = builder
            .WithSigningCertificateForm(XadesSigningCertificateForm.V1)
            .WithSignaturePolicy(current.ToReference());
        if (timestamp is null)
        {
            return builder;
        }

        builder = builder.WithLevel(AdesBaselineProfile.Timestamped(timestamp));
        return policy switch
        {
            IcpBrasilPolicy.AdRv => builder.WithExtendedValidationData(XadesExtendedForm.CompleteReferences),
            IcpBrasilPolicy.AdRc => builder.WithExtendedValidationData(XadesExtendedForm.ExtendedLong),
            IcpBrasilPolicy.AdRa => builder.WithExtendedValidationData(XadesExtendedForm.Archive),
            _ => builder,
        };
    }
}
