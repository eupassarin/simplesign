namespace SimpleSign.Brasil.IcpBrasil;

/// <summary>
/// ICP-Brasil signature policy types (AD = Assinatura Digital), per DOC-ICP-15.03.
/// PAdES has no AD-RV policy.
/// </summary>
public enum IcpBrasilPolicy
{
    /// <summary>AD-RB — Digital Signature with Basic Reference.</summary>
    AdRb,

    /// <summary>AD-RT — Digital Signature with Time Reference (requires timestamp).</summary>
    AdRt,

    /// <summary>AD-RV — Digital Signature with Validation Reference.</summary>
    AdRv,

    /// <summary>AD-RC — Digital Signature with Complete References.</summary>
    AdRc,

    /// <summary>AD-RA — Digital Signature with Archival References.</summary>
    AdRa,
}

/// <summary>
/// ICP-Brasil certificate type, from the certificate policy OID 2.16.76.1.2.{type}.{n}
/// in the certificate's CertificatePolicies (ADE-ICP-04.01).
/// </summary>
public enum IcpBrasilCertificateLevel
{
    /// <summary>A1 — Software-generated key, validity up to 1 year.</summary>
    A1,
    /// <summary>A2 — Software or hardware-generated key, validity up to 2 years.</summary>
    A2,
    /// <summary>A3 — Key generated in cryptographic hardware (token/smartcard), validity up to 5 years.</summary>
    A3,
    /// <summary>A4 — Key generated in high-level hardware, validity up to 6 years.</summary>
    A4,
    /// <summary>S1 — Confidentiality certificate, software key, validity up to 1 year.</summary>
    S1,
    /// <summary>S2 — Confidentiality certificate, software or hardware key, validity up to 2 years.</summary>
    S2,
    /// <summary>S3 — Confidentiality certificate, hardware key (token/smartcard), validity up to 5 years.</summary>
    S3,
    /// <summary>S4 — Confidentiality certificate, high-level hardware key, validity up to 6 years.</summary>
    S4,

    /// <summary>T3 — Timestamp (ACT) certificate, policy 2.16.76.1.2.303.</summary>
    T3,

    /// <summary>T4 — Timestamp (ACT) certificate, policy 2.16.76.1.2.304.</summary>
    T4,

    /// <summary>A CF-e-SAT — Certificate for the SAT fiscal equipment, policy 2.16.76.1.2.500.</summary>
    ACfeSat,

    /// <summary>OM-BR — Certificate for metrology objects, policy 2.16.76.1.2.550.</summary>
    OmBr,
}
