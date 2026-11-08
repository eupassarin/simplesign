using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Validation;

namespace SimpleSign.Core.Policies;

/// <summary>What <see cref="ValidationPolicy"/> and <see cref="SigningPolicy"/> share: the tree, the suites, the JSON.</summary>
internal sealed class PolicyTree
{
    public PolicyTree(PolicyNode root, IReadOnlyDictionary<string, CryptographicSuite> suites)
    {
        Root = root;
        Suites = suites;
        _digest = new Lazy<string>(ComputeDigest);
    }

    private readonly Lazy<string> _digest;

    public PolicyNode Root { get; }

    public IReadOnlyDictionary<string, CryptographicSuite> Suites { get; }

    public string? Name => Root.Attributes.TryGetValue("Name", out var name) ? (string)name : null;

    public string? Description => Root.Child("Description")?.Text;

    public string Digest => _digest.Value;

    public PolicyConstraint? Find(string path) => Root.Find(path)?.ToConstraint();

    /// <summary>The level of the element at <paramref name="path"/>; <see cref="ConstraintLevel.Ignore"/> when it is absent or has none.</summary>
    public ConstraintLevel Level(string path) => Root.Find(path)?.Level ?? ConstraintLevel.Ignore;

    public PolicyTree With(string path, PolicyConstraint? constraint)
    {
        ArgumentNullException.ThrowIfNull(path);
        var root = Root.Clone();
        root.Set(path, constraint);
        return new PolicyTree(root, Suites);
    }

    public PolicyTree WithName(string? name, string? description)
    {
        var root = Root.Clone();
        if (name is null)
        {
            root.Attributes.Remove("Name");
        }
        else
        {
            root.Attributes["Name"] = name;
        }

        if (description is not null)
        {
            var node = root.Child("Description");
            if (node is null)
            {
                node = new PolicyNode("Description", "String");
                root.Insert(node);
            }

            node.Text = description;
        }

        return new PolicyTree(root, Suites);
    }

    public PolicyTree WithSuite(CryptographicSuite suite, string? context)
    {
        ArgumentNullException.ThrowIfNull(suite);
        string key = Normalize(context ?? "");
        if (key.Length > 0 && Root.Find(key) is null && !IsSchemaPath(key))
        {
            throw new ArgumentException($"'{context}' is not a context of the policy.", nameof(context));
        }

        var suites = new Dictionary<string, CryptographicSuite>(Suites, StringComparer.Ordinal) { [key] = suite };
        return new PolicyTree(Root, suites);
    }

    /// <summary>
    /// The cryptographic rules of the context at <paramref name="contextPath"/>: a suite given for it or an enclosing
    /// context (the global suite last) wins; otherwise its <c>Cryptographic</c> elements, then those of the enclosing
    /// elements, then the global one.
    /// </summary>
    public CryptographicRules Crypto(string contextPath)
    {
        string path = Normalize(contextPath);
        var prefixes = Prefixes(path).ToList();
        foreach (string prefix in prefixes)
        {
            if (Suites.TryGetValue(prefix, out var suite))
            {
                return CryptographicRules.From(suite);
            }
        }

        return CryptographicRules.From(prefixes.Select(p => Root.Find(p.Length == 0 ? "Cryptographic" : p + "/Cryptographic")));
    }

    public string ToJson() => PolicyJson.Write(Root, Root.Name == PolicySchema.ValidationRoot ? PolicyJsonSchema.ValidationUri : PolicyJsonSchema.SigningUri);

    public static PolicyTree Parse(string json, string rootName, string what)
    {
        ArgumentNullException.ThrowIfNull(json);
        try
        {
            return new PolicyTree(PolicyJson.Read(json, rootName), new Dictionary<string, CryptographicSuite>(StringComparer.Ordinal));
        }
        catch (Exception ex) when (ex is System.Text.Json.JsonException or FormatException or InvalidOperationException)
        {
            throw new InvalidDataException($"The {what} is not valid: {ex.Message}", ex);
        }
    }

    public static PolicyTree LoadSigned(string path, string signaturePath, X509Certificate2 trustedSigner, string rootName, string what)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentException.ThrowIfNullOrWhiteSpace(signaturePath);
        ArgumentNullException.ThrowIfNull(trustedSigner);
        byte[] content = File.ReadAllBytes(path);
        DetachedSignature.Verify(content, File.ReadAllBytes(signaturePath), trustedSigner, what);
        return Parse(Encoding.UTF8.GetString(content), rootName, what);
    }

    private string ComputeDigest()
    {
        var text = new StringBuilder(ToJson());
        foreach (var (context, suite) in Suites.OrderBy(s => s.Key, StringComparer.Ordinal))
        {
            text.Append('\n').Append(context).Append('\n').Append(suite.Json);
        }

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text.ToString())));
    }

    private bool IsSchemaPath(string path)
    {
        string type = Root.Type;
        foreach (string part in path.Split('/'))
        {
            if (PolicySchema.Get(type).ChildType(part) is not { } child)
            {
                return false;
            }

            type = child;
        }

        return true;
    }

    private static string Normalize(string path) => string.Join('/', path.Split('/', StringSplitOptions.RemoveEmptyEntries));

    /// <summary>The path and each enclosing path, ending with the empty (root) path.</summary>
    private static IEnumerable<string> Prefixes(string path)
    {
        string current = path;
        while (current.Length > 0)
        {
            yield return current;
            int slash = current.LastIndexOf('/');
            current = slash < 0 ? "" : current[..slash];
        }

        yield return "";
    }
}

/// <summary>Reads the policies embedded in this assembly.</summary>
internal static class PolicyResources
{
    internal static string Read(string fileName)
    {
        string name = "SimpleSign.Core.Policies.Default." + fileName;
        using var stream = typeof(PolicyResources).Assembly.GetManifestResourceStream(name)
            ?? throw new InvalidOperationException($"Embedded policy '{name}' not found.");
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }
}

/// <summary>Checks a detached CMS signature over a configuration file.</summary>
internal static class DetachedSignature
{
    internal static void Verify(byte[] content, byte[] signature, X509Certificate2 trustedSigner, string what)
    {
        CmsSignedData cms;
        try
        {
            cms = CmsParser.Parse(signature);
        }
        catch (Exception ex) when (ex is System.Formats.Asn1.AsnContentException or CryptographicException or InvalidDataException)
        {
            throw new CryptographicException($"The signature of the {what} cannot be read.", ex);
        }

        if (cms.SignerCertificate is null || !cms.SignerCertificate.RawData.AsSpan().SequenceEqual(trustedSigner.RawData))
        {
            throw new CryptographicException($"The {what} is not signed by the trusted certificate '{trustedSigner.Subject}'.");
        }

        HashAlgorithmName hash = cms.DigestAlgorithmOid switch
        {
            "2.16.840.1.101.3.4.2.1" => HashAlgorithmName.SHA256,
            "2.16.840.1.101.3.4.2.2" => HashAlgorithmName.SHA384,
            "2.16.840.1.101.3.4.2.3" => HashAlgorithmName.SHA512,
            _ => throw new CryptographicException($"The signature of the {what} uses an unsupported digest algorithm."),
        };

        if (cms.SignedAttrs is null)
        {
            // No signed attributes: the signature is over the content itself (RFC 5652 §5.4).
            if (cms.Signature is null || !VerifyOver(content, cms.Signature, cms.SignerCertificate, hash))
            {
                throw new CryptographicException($"The signature does not cover this {what}: it was changed after it was signed, or the signature is wrong.");
            }

            return;
        }

        if (!CryptoVerifier.VerifySignature(cms))
        {
            throw new CryptographicException($"The signature of the {what} does not verify.");
        }

        if (cms.MessageDigest is null || !CryptographicOperations.FixedTimeEquals(cms.MessageDigest, CryptoUtility.ComputeHash(content, hash)))
        {
            throw new CryptographicException($"The signature does not cover this {what}: it was changed after it was signed.");
        }
    }

    private static bool VerifyOver(byte[] content, byte[] signature, X509Certificate2 signer, HashAlgorithmName hash)
    {
        using var rsa = signer.GetRSAPublicKey();
        if (rsa is not null)
        {
            return rsa.VerifyData(content, signature, hash, RSASignaturePadding.Pkcs1);
        }

        using var ecdsa = signer.GetECDsaPublicKey();
        return ecdsa is not null && ecdsa.VerifyData(content, signature, hash, DSASignatureFormat.Rfc3279DerSequence);
    }
}
