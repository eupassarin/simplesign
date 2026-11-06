namespace SimpleSign.XAdES.Constants;

/// <summary>Standard URIs, namespaces, and ID prefixes for XAdES (ETSI EN 319 132).</summary>
public static class XadesUris
{
    /// <summary>XAdES v1.3.2 namespace.</summary>
    public const string XadesNamespace = "http://uri.etsi.org/01903/v1.3.2#";

    /// <summary>XAdES v1.4.1 namespace (v1.4.2 namespace is identical).</summary>
    public const string Xades141Namespace = "http://uri.etsi.org/01903/v1.4.1#";

    /// <summary>SignedProperties type URI for XAdES.</summary>
    public const string SignedPropertiesType = "http://uri.etsi.org/01903#SignedProperties";

    /// <summary>ID prefix for Signature elements.</summary>
    public const string SignatureIdPrefix = "S-";

    /// <summary>ID prefix for SignedProperties elements.</summary>
    public const string SignedPropertiesIdPrefix = "SignedProperties-";

    /// <summary>ID prefix for SignatureTimeStamp elements.</summary>
    public const string SignatureTimeStampIdPrefix = "TS-";

    /// <summary>ID prefix for CertificateValues elements.</summary>
    public const string CertificateValuesIdPrefix = "CV-";

    /// <summary>ID prefix for RevocationValues elements.</summary>
    public const string RevocationValuesIdPrefix = "RV-";

    /// <summary>ID prefix for ArchiveTimeStamp elements.</summary>
    public const string ArchiveTimeStampIdPrefix = "ATS-";
}
