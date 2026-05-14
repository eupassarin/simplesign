namespace SimpleSign.Core.Inspection;

/// <summary>
/// Identifies a cryptographic algorithm by its OID and friendly name.
/// </summary>
public sealed class AlgorithmInfo
{
    /// <summary>ASN.1 Object Identifier (e.g., "2.16.840.1.101.3.4.2.1" for SHA-256).</summary>
    public string Oid { get; init; } = string.Empty;

    /// <summary>Human-readable algorithm name (e.g., "SHA-256", "RSA-SHA256").</summary>
    public string Name { get; init; } = string.Empty;

    internal static AlgorithmInfo FromOid(string oid)
    {
        return new AlgorithmInfo
        {
            Oid = oid,
            Name = MapOidToName(oid)
        };
    }

    /// <summary>Creates an <see cref="AlgorithmInfo"/> from an XMLDSig algorithm URI.</summary>
    internal static AlgorithmInfo FromUri(string uri)
    {
        return new AlgorithmInfo
        {
            Oid = uri,
            Name = MapUriToName(uri)
        };
    }

    private static string MapUriToName(string uri) => uri switch
    {
        Constants.XmlDSigUrls.Sha1Digest => "SHA-1",
        Constants.XmlDSigUrls.Sha256Digest => "SHA-256",
        Constants.XmlDSigUrls.Sha384Digest => "SHA-384",
        Constants.XmlDSigUrls.Sha512Digest => "SHA-512",
        Constants.XmlDSigUrls.RsaSha1 => "RSA-SHA1",
        Constants.XmlDSigUrls.RsaSha256 => "RSA-SHA256",
        Constants.XmlDSigUrls.RsaSha384 => "RSA-SHA384",
        Constants.XmlDSigUrls.RsaSha512 => "RSA-SHA512",
        Constants.XmlDSigUrls.EcdsaSha256 => "ECDSA-SHA256",
        Constants.XmlDSigUrls.EcdsaSha384 => "ECDSA-SHA384",
        Constants.XmlDSigUrls.EcdsaSha512 => "ECDSA-SHA512",
        _ => uri
    };

    private static string MapOidToName(string oid) => oid switch
    {
        Constants.Oids.Sha1 => "SHA-1",
        Constants.Oids.Sha256 => "SHA-256",
        Constants.Oids.Sha384 => "SHA-384",
        Constants.Oids.Sha512 => "SHA-512",
        Constants.Oids.RsaSha1 => "RSA-SHA1",
        Constants.Oids.RsaSha256 => "RSA-SHA256",
        Constants.Oids.RsaSha384 => "RSA-SHA384",
        Constants.Oids.RsaSha512 => "RSA-SHA512",
        Constants.Oids.RsaPss => "RSA-PSS",
        Constants.Oids.RsaEncryption => "RSA",
        Constants.Oids.EcdsaSha256 => "ECDSA-SHA256",
        Constants.Oids.EcdsaSha384 => "ECDSA-SHA384",
        Constants.Oids.EcdsaSha512 => "ECDSA-SHA512",
        Constants.Oids.Ed25519 => "Ed25519",
        Constants.Oids.Ed448 => "Ed448",
        _ => oid
    };

    /// <inheritdoc />
    public override string ToString() => string.IsNullOrEmpty(Name) ? Oid : $"{Name} ({Oid})";
}
