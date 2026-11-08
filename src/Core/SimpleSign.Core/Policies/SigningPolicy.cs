using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Signing;

namespace SimpleSign.Core.Policies;

/// <summary>A check of a <see cref="SigningPolicy"/> that the certificate does not pass.</summary>
/// <param name="Constraint">The constraint's path, such as <c>SigningCertificate/KeyUsage</c>.</param>
/// <param name="Level">The constraint's level.</param>
/// <param name="Reason">The reason a refusal carries.</param>
/// <param name="Message">What was found.</param>
public sealed record SigningPolicyFinding(string Constraint, ConstraintLevel Level, SigningErrorReason Reason, string Message);

/// <summary>
/// The checks a signer makes before it signs, written as JSON in the style of the EU DSS validation policy (root
/// <c>SigningConstraints</c>): <c>SigningCertificate</c> and <c>CACertificate</c> with the DSS names
/// (<c>NotExpired</c>, <c>KeyUsage</c>, <c>ExtendedKeyUsage</c>, <c>NotRevoked</c>, <c>RevocationDataAvailable</c>,
/// <c>Cryptographic</c>) and a <c>Cryptographic</c> element for the signature to be made. Levels: FAIL refuses the
/// signature (<see cref="SigningException"/>), WARN adds a <see cref="SigningWarning"/>, INFORM logs.
/// </summary>
/// <remarks>
/// <see cref="Default"/> checks the validity of the chain, the key usage of the signing certificate (digitalSignature or
/// nonRepudiation), the key (RSA and RSASSA-PSS 2048 bits, ECDSA 256 bits) and the digest (SHA-2, SHA-3). Revocation is
/// checked when <c>NotRevoked</c> or <c>RevocationDataAvailable</c> is not IGNORE; it needs the whole chain and the
/// network.
/// </remarks>
public sealed class SigningPolicy
{
    private static readonly Lazy<SigningPolicy> s_default =
        new(() => FromJson(PolicyResources.Read("signing-policy.json")), LazyThreadSafetyMode.ExecutionAndPublication);

    private SigningPolicy(PolicyTree tree)
    {
        Tree = tree;
    }

    internal PolicyTree Tree { get; }

    /// <summary>The policy embedded in SimpleSign.</summary>
    public static SigningPolicy Default => s_default.Value;

    /// <summary>The policy's name (<c>Name</c>), or null.</summary>
    public string? Name => Tree.Name;

    /// <summary>The policy's description (<c>Description</c>), or null.</summary>
    public string? Description => Tree.Description;

    /// <summary>The SHA-256 (hex) of the policy as written by <see cref="ToJson"/>, with its suites.</summary>
    public string Digest => Tree.Digest;

    /// <summary>The constraint at <paramref name="path"/>, such as <c>SigningCertificate/KeyUsage</c>.</summary>
    /// <param name="path">The element names from the root, separated by <c>/</c>.</param>
    /// <returns>The constraint, or null when the policy does not have it.</returns>
    public PolicyConstraint? Find(string path) => Tree.Find(path);

    /// <summary>A copy of the policy with another name and, when given, another description.</summary>
    /// <param name="name">The name.</param>
    /// <param name="description">The description, or null to keep the current one.</param>
    /// <returns>The new policy.</returns>
    public SigningPolicy WithName(string name, string? description = null)
    {
        ArgumentNullException.ThrowIfNull(name);
        return new(Tree.WithName(name, description));
    }

    /// <summary>A copy of the policy with the constraint at <paramref name="path"/> set, or removed when <paramref name="constraint"/> is null.</summary>
    /// <param name="path">The element names from the root, separated by <c>/</c>.</param>
    /// <param name="constraint">The constraint, or null to remove it.</param>
    /// <returns>The new policy.</returns>
    /// <exception cref="ArgumentException">The path is not in the signing policy schema.</exception>
    public SigningPolicy With(string path, PolicyConstraint? constraint) => new(Tree.With(path, constraint));

    /// <summary>A copy of the policy whose cryptographic constraints come from <paramref name="suite"/>, everywhere or in one context.</summary>
    /// <param name="suite">The ETSI TS 119 322 suite.</param>
    /// <param name="context">The context path (<c>SigningCertificate</c>, <c>CACertificate</c>), or null for every context.</param>
    /// <returns>The new policy.</returns>
    public SigningPolicy WithCryptographicSuite(CryptographicSuite suite, string? context = null) => new(Tree.WithSuite(suite, context));

    /// <summary>Reads a policy from JSON (root object <c>SigningConstraints</c>).</summary>
    /// <param name="json">The JSON document.</param>
    /// <returns>The policy.</returns>
    /// <exception cref="InvalidDataException">The JSON is not a signing policy.</exception>
    public static SigningPolicy FromJson(string json) => new(PolicyTree.Parse(json, PolicySchema.SigningRoot, "signing policy"));

    /// <summary>Reads a policy from a JSON file.</summary>
    /// <param name="path">The file path.</param>
    /// <returns>The policy.</returns>
    public static SigningPolicy Load(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return FromJson(File.ReadAllText(path));
    }

    /// <summary>Reads a policy from a JSON file after checking its detached CMS signature by <paramref name="trustedSigner"/>.</summary>
    /// <param name="path">The JSON file.</param>
    /// <param name="signaturePath">The detached CMS signature (DER) of the file.</param>
    /// <param name="trustedSigner">The certificate the policy must be signed with.</param>
    /// <returns>The policy.</returns>
    /// <exception cref="CryptographicException">The signature does not verify, does not cover the file, or is not by the trusted signer.</exception>
    public static SigningPolicy LoadSigned(string path, string signaturePath, X509Certificate2 trustedSigner) =>
        new(PolicyTree.LoadSigned(path, signaturePath, trustedSigner, PolicySchema.SigningRoot, "signing policy"));

    /// <summary>
    /// The JSON Schema (draft 2020-12) of the policy files, generated from the policy schema: editors use it to complete
    /// and check a policy. <see cref="ToJson"/> writes its address in <c>$schema</c>.
    /// </summary>
    /// <returns>The JSON Schema document.</returns>
    public static string GetJsonSchema() => PolicyJsonSchema.Generate(PolicySchema.SigningRoot);

    /// <summary>Writes the policy as indented JSON, in the form <see cref="FromJson"/> reads.</summary>
    /// <returns>The JSON document.</returns>
    public string ToJson() => Tree.ToJson();

    /// <summary>Whether the revocation of the chain is to be checked before signing.</summary>
    internal bool ChecksRevocation =>
        Tree.Level("SigningCertificate/NotRevoked") != ConstraintLevel.Ignore
        || Tree.Level("SigningCertificate/RevocationDataAvailable") != ConstraintLevel.Ignore
        || Tree.Level("CACertificate/NotRevoked") != ConstraintLevel.Ignore
        || Tree.Level("CACertificate/RevocationDataAvailable") != ConstraintLevel.Ignore;

    /// <summary>
    /// The checks of the signing certificate that need neither its chain nor the network: validity at
    /// <paramref name="time"/>, key usage, extended key usage, and the key under the policy's <c>Cryptographic</c>.
    /// </summary>
    /// <param name="certificate">The signing certificate.</param>
    /// <param name="time">The time of signing.</param>
    /// <returns>The checks it does not pass (with any level other than IGNORE).</returns>
    public IReadOnlyList<SigningPolicyFinding> Evaluate(X509Certificate2 certificate, DateTimeOffset time)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        var findings = new List<SigningPolicyFinding>();

        void Add(string path, SigningErrorReason reason, string message)
        {
            var level = Tree.Level(path);
            if (level != ConstraintLevel.Ignore)
            {
                findings.Add(new SigningPolicyFinding(path, level, reason, message));
            }
        }

        if (certificate.NotBefore.ToUniversalTime() > time)
        {
            Add("SigningCertificate/NotExpired", SigningErrorReason.CertificateNotCurrentlyValid,
                $"Certificate '{certificate.Subject}' is not valid until {certificate.NotBefore.ToUniversalTime():yyyy-MM-dd} UTC.");
        }
        else if (certificate.NotAfter.ToUniversalTime() < time)
        {
            Add("SigningCertificate/NotExpired", SigningErrorReason.CertificateExpired,
                $"Certificate '{certificate.Subject}' expired on {certificate.NotAfter.ToUniversalTime():yyyy-MM-dd} UTC.");
        }

        if (Tree.Find("SigningCertificate/KeyUsage") is { EffectiveLevel: not ConstraintLevel.Ignore } keyUsage
            && !CertificateFacts.HasAnyKeyUsage(certificate, keyUsage.Ids))
        {
            Add("SigningCertificate/KeyUsage", SigningErrorReason.KeyUsageNotPermitted,
                $"Certificate '{certificate.Subject}' does not allow digital signatures: its key usage has none of {string.Join(", ", keyUsage.Ids)}.");
        }

        if (Tree.Find("SigningCertificate/ExtendedKeyUsage") is { EffectiveLevel: not ConstraintLevel.Ignore } extendedKeyUsage
            && !CertificateFacts.HasAnyExtendedKeyUsage(certificate, extendedKeyUsage.Ids))
        {
            Add("SigningCertificate/ExtendedKeyUsage", SigningErrorReason.KeyUsageNotPermitted,
                $"Certificate '{certificate.Subject}' has none of the extended key usages {string.Join(", ", extendedKeyUsage.Ids)}.");
        }

        if (CryptographicRules.KeyOf(certificate) is { } key)
        {
            foreach (var finding in Tree.Crypto("").CheckKey(key.Algorithm, key.Size, time))
            {
                findings.Add(new SigningPolicyFinding("Cryptographic/" + finding.Id, finding.Level,
                    finding.Id == "MiniPublicKeySize" ? SigningErrorReason.KeyTooWeak : SigningErrorReason.AlgorithmNotPermitted,
                    $"The key of '{certificate.Subject}': {finding.Message}"));
            }
        }

        return findings;
    }

    /// <summary>The checks of the digest algorithm of the signature to be made, at <paramref name="time"/>.</summary>
    internal IReadOnlyList<SigningPolicyFinding> EvaluateDigest(HashAlgorithmName hash, DateTimeOffset time) =>
        [.. Tree.Crypto("").CheckDigest(CryptographicRules.DigestName(hash), time)
            .Select(f => new SigningPolicyFinding("Cryptographic/" + f.Id, f.Level, SigningErrorReason.AlgorithmNotPermitted,
                $"{f.Message} (signing policy)"))];
}
