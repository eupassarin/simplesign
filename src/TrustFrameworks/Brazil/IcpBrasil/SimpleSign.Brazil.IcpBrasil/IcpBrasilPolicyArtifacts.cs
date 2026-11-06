using System.Security.Cryptography;
using SimpleSign.PAdES.Signing;

namespace SimpleSign.Brazil.IcpBrasil;

/// <summary>
/// The policy artifacts an ICP-Brasil PAdES AD-RA signature must embed in the DSS
/// (DOC-ICP-15.03, Annex 4 §2.4): the PA it was made under, the LPA in force at signing time and
/// the LPA's signature, as published by the ITI.
/// </summary>
/// <param name="Policy">The policy these artifacts are for.</param>
/// <param name="PolicyDocument">The PA file (e.g. <c>PA_PAdES_AD_RA_v1_4.der</c>).</param>
/// <param name="Lpa">The policy list (<c>LPA_PAdES.der</c>).</param>
/// <param name="LpaSignature">The LPA's detached signature (<c>LPA_PAdES.p7s</c>).</param>
public sealed record IcpBrasilPolicyArtifacts(
    IcpBrasilSignaturePolicy Policy,
    ReadOnlyMemory<byte> PolicyDocument,
    ReadOnlyMemory<byte> Lpa,
    ReadOnlyMemory<byte> LpaSignature)
{
    /// <summary>DSS array of the PA documents.</summary>
    public const string DssPolicyArtifacts = "PBAD_PolicyArtifacts";

    /// <summary>DSS array of the LPAs.</summary>
    public const string DssLpaArtifacts = "PBAD_LpaArtifacts";

    /// <summary>DSS array of the LPA signatures.</summary>
    public const string DssLpaSignatures = "PBAD_LpaSignatures";

    /// <summary>VRI entry referencing the PA document.</summary>
    public const string VriPolicyArtifact = "PBAD_PolicyArtifact";

    /// <summary>VRI entry referencing the LPA.</summary>
    public const string VriLpaArtifact = "PBAD_LpaArtifact";

    /// <summary>VRI entry referencing the LPA signature.</summary>
    public const string VriLpaSignature = "PBAD_LpaSignature";

    /// <summary>
    /// Downloads the current <c>LPA_PAdES</c> and its signature from the ITI repository, checks
    /// that the ITI signed it, finds <paramref name="policy"/> in it and downloads the PA, checking
    /// it against the digest the LPA lists.
    /// </summary>
    /// <param name="httpClient">HTTP client for the ITI repository, LCRs and AIA.</param>
    /// <param name="policy">The PAdES policy version the signature uses.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="CryptographicException">The LPA signature or the PA digest does not verify.</exception>
    /// <exception cref="IcpBrasilPolicyException">The LPA does not list the policy.</exception>
    public static Task<IcpBrasilPolicyArtifacts> DownloadAsync(
        HttpClient httpClient, IcpBrasilSignaturePolicy policy, CancellationToken cancellationToken = default) =>
        DownloadAsync(httpClient, policy, chainValidator: null, cancellationToken);

    internal static async Task<IcpBrasilPolicyArtifacts> DownloadAsync(
        HttpClient httpClient, IcpBrasilSignaturePolicy policy, IcpBrasilChainValidator? chainValidator, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(policy);
        if (policy.Info.Format != IcpBrasilPolicyFormat.Pades)
        {
            throw new ArgumentException("Policy artifacts are embedded in PAdES signatures only.", nameof(policy));
        }

        byte[] lpa = await IcpBrasilSignaturePolicies.DownloadFromRepositoryAsync(httpClient, "LPA_PAdES.der", cancellationToken).ConfigureAwait(false);
        byte[] signature = await IcpBrasilSignaturePolicies.DownloadFromRepositoryAsync(httpClient, "LPA_PAdES.p7s", cancellationToken).ConfigureAwait(false);
        await IcpBrasilSignaturePolicies.VerifyLpaSignatureAsync(lpa, signature, httpClient, cancellationToken, chainValidator).ConfigureAwait(false);

        var entry = IcpBrasilLpa.Parse(lpa).Entries.FirstOrDefault(e => e.Oid == policy.Oid)
            ?? throw new IcpBrasilPolicyException($"The current LPA_PAdES does not list the policy {policy.Oid}.");
        byte[] pa = await IcpBrasilSignaturePolicies.DownloadAsync(
            httpClient, IcpBrasilSignaturePolicies.ToHttps(new Uri(entry.Uri)), cancellationToken).ConfigureAwait(false);
        if (!CryptographicOperations.FixedTimeEquals(IcpBrasilSignaturePolicies.HashData(entry.DigestAlgorithmOid, pa), entry.Digest.Span))
        {
            throw new CryptographicException($"The PA at {entry.Uri} does not match the digest listed in LPA_PAdES.");
        }

        return new IcpBrasilPolicyArtifacts(policy, pa, lpa, signature);
    }

    /// <summary>The DSS artifacts to embed, with the VRI references of the signature.</summary>
    public IReadOnlyList<PdfDssArtifact> ToDssArtifacts() =>
    [
        new PdfDssArtifact(DssPolicyArtifacts, VriPolicyArtifact, PolicyDocument),
        new PdfDssArtifact(DssLpaArtifacts, VriLpaArtifact, Lpa),
        new PdfDssArtifact(DssLpaSignatures, VriLpaSignature, LpaSignature),
    ];
}
