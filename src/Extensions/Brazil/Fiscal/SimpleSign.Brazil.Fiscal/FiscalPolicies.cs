using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.Core.Policies;

namespace SimpleSign.Brazil.Fiscal;

/// <summary>The signing policies of the fiscal layouts.</summary>
public static class FiscalPolicies
{
    /// <summary>
    /// The SEFAZ layouts (NF-e, NFC-e, CT-e, MDF-e and their events): <see cref="IcpBrasilPolicies.Signing"/> (an
    /// ICP-Brasil chain, not revoked, RSA 2048 bits or more…) with SHA-1 accepted as the signature digest, because the
    /// layouts mandate RSA-SHA1. Nothing else is relaxed: the CA certificates of the chain must still be signed with SHA-2.
    /// </summary>
    public static SigningPolicy Sefaz { get; } = IcpBrasilPolicies.Signing
        // The CA certificates keep the SHA-2/SHA-3 rule: their own list, so the SHA-1 below does not reach them.
        .With("CACertificate/Cryptographic/AcceptableDigestAlgo", new PolicyConstraint(null)
        {
            Algorithms = [new("SHA256"), new("SHA384"), new("SHA512"), new("SHA3-256"), new("SHA3-384"), new("SHA3-512")],
        })
        .WithName("ICP-Brasil fiscal (SEFAZ)", "The checks of the ICP-Brasil signing policy, with SHA-1 accepted as the digest: the SEFAZ layouts (NF-e, CT-e, MDF-e) mandate RSA-SHA1.")
        .With("Cryptographic/AcceptableDigestAlgo", new PolicyConstraint(null)
        {
            Algorithms = [new("SHA1"), new("SHA256"), new("SHA384"), new("SHA512"), new("SHA3-256"), new("SHA3-384"), new("SHA3-512")],
        });
}
