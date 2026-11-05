namespace SimpleSign.XAdES;

/// <summary>Which signing-certificate property identifies the signer certificate.</summary>
public enum XadesSigningCertificateForm
{
    /// <summary>SigningCertificateV2 (ETSI EN 319 132-1), the default.</summary>
    V2,

    /// <summary>
    /// SigningCertificate (XAdES 1.3.2, ETSI TS 101 903): CertDigest plus IssuerSerial (issuer
    /// DN and serial number). Required by the ICP-Brasil XML signature policies.
    /// </summary>
    V1,
}
