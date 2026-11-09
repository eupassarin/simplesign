using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Core.Policies;

/// <summary>
/// A validation policy as JSON (root <c>ValidationConstraints</c>): the constraints the validator checks, grouped by
/// what they apply to (the signature, countersignatures, timestamps, revocation data, trusted lists), each with a level
/// (FAIL, WARN, INFORM, IGNORE); one JSON property per element, attributes as properties, the <c>Id</c> and
/// <c>Algo</c> lists as arrays. A constraint left out is not evaluated; a constraint SimpleSign does not evaluate yet
/// is reported as not checked.
/// </summary>
/// <remarks>
/// <see cref="Default"/> is the policy embedded in SimpleSign. A policy is immutable: <see cref="With"/> and
/// <see cref="WithCryptographicSuite"/> return a new one.
/// </remarks>
public sealed class ValidationPolicy
{
    private static readonly Lazy<ValidationPolicy> s_default =
        new(() => FromJson(PolicyResources.Read("validation-policy.json")), LazyThreadSafetyMode.ExecutionAndPublication);

    private ValidationPolicy(PolicyTree tree)
    {
        Tree = tree;
    }

    internal PolicyTree Tree { get; }

    /// <summary>The policy embedded in SimpleSign: the constraints and levels SimpleSign recommends.</summary>
    public static ValidationPolicy Default => s_default.Value;

    /// <summary>The policy's name (<c>Name</c>), or null.</summary>
    public string? Name => Tree.Name;

    /// <summary>The policy's description (<c>Description</c>), or null.</summary>
    public string? Description => Tree.Description;

    /// <summary>The SHA-256 (hex) of the policy as written by <see cref="ToJson"/>, with its suites: identifies the policy in reports.</summary>
    public string Digest => Tree.Digest;

    /// <summary>The cryptographic suites given with <see cref="WithCryptographicSuite"/>, by context path (empty for the global one).</summary>
    public IReadOnlyDictionary<string, CryptographicSuite> CryptographicSuites => Tree.Suites;

    /// <summary>The constraint at <paramref name="path"/>, such as <c>SignatureConstraints/BasicSignatureConstraints/SigningCertificate/KeyUsage</c>.</summary>
    /// <param name="path">The element names from the root, separated by <c>/</c>.</param>
    /// <returns>The constraint, or null when the policy does not have it.</returns>
    public PolicyConstraint? Find(string path) => Tree.Find(path);

    /// <summary>A copy of the policy with another name and, when given, another description.</summary>
    /// <param name="name">The name.</param>
    /// <param name="description">The description, or null to keep the current one.</param>
    /// <returns>The new policy.</returns>
    public ValidationPolicy WithName(string name, string? description = null)
    {
        ArgumentNullException.ThrowIfNull(name);
        return new(Tree.WithName(name, description));
    }

    /// <summary>A copy of the policy with the constraint at <paramref name="path"/> set, or removed when <paramref name="constraint"/> is null.</summary>
    /// <param name="path">The element names from the root, separated by <c>/</c>; the enclosing elements are created as needed.</param>
    /// <param name="constraint">The constraint, or null to remove it.</param>
    /// <returns>The new policy.</returns>
    /// <exception cref="ArgumentException">The path is not in the policy schema.</exception>
    public ValidationPolicy With(string path, PolicyConstraint? constraint) => new(Tree.With(path, constraint));

    /// <summary>
    /// A copy of the policy whose cryptographic constraints come from <paramref name="suite"/>: for every context, or
    /// only for the context at <paramref name="context"/> and the contexts inside it (for example
    /// <c>SignatureConstraints/BasicSignatureConstraints/SigningCertificate</c>).
    /// </summary>
    /// <param name="suite">The ETSI TS 119 322 suite.</param>
    /// <param name="context">The context path, or null for every context.</param>
    /// <returns>The new policy.</returns>
    public ValidationPolicy WithCryptographicSuite(CryptographicSuite suite, string? context = null) => new(Tree.WithSuite(suite, context));

    /// <summary>Reads a policy from JSON (root object <c>ValidationConstraints</c>).</summary>
    /// <param name="json">The JSON document.</param>
    /// <returns>The policy.</returns>
    /// <exception cref="InvalidDataException">The JSON is not a policy, or uses a name outside the policy schema.</exception>
    public static ValidationPolicy FromJson(string json) => new(PolicyTree.Parse(json, PolicySchema.ValidationRoot, "validation policy"));

    /// <summary>Reads a policy from a JSON file.</summary>
    /// <param name="path">The file path.</param>
    /// <returns>The policy.</returns>
    public static ValidationPolicy Load(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return FromJson(File.ReadAllText(path));
    }

    /// <summary>
    /// Reads a policy from a JSON file after checking its detached CMS signature: the signature must verify, cover the
    /// file's bytes and be made by <paramref name="trustedSigner"/>.
    /// </summary>
    /// <param name="path">The JSON file.</param>
    /// <param name="signaturePath">The detached CMS signature (DER) of the file.</param>
    /// <param name="trustedSigner">The certificate the policy must be signed with.</param>
    /// <returns>The policy.</returns>
    /// <exception cref="System.Security.Cryptography.CryptographicException">The signature does not verify, does not cover the file, or is not by the trusted signer.</exception>
    public static ValidationPolicy LoadSigned(string path, string signaturePath, X509Certificate2 trustedSigner) =>
        new(PolicyTree.LoadSigned(path, signaturePath, trustedSigner, PolicySchema.ValidationRoot, "validation policy"));

    /// <summary>
    /// The JSON Schema (draft 2020-12) of the policy files, generated from the policy schema: editors use it to complete
    /// and check a policy. <see cref="ToJson"/> writes its address in <c>$schema</c>.
    /// </summary>
    /// <returns>The JSON Schema document.</returns>
    public static string GetJsonSchema() => PolicyJsonSchema.Generate(PolicySchema.ValidationRoot);

    /// <summary>Writes the policy as indented JSON, in the form <see cref="FromJson"/> reads (the suites are not included).</summary>
    /// <returns>The JSON document.</returns>
    public string ToJson() => Tree.ToJson();
}
