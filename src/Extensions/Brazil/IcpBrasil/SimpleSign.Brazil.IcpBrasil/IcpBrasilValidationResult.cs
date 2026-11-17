using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Brazil.IcpBrasil;

/// <summary>ICP-Brasil chain validation result.</summary>
public sealed class IcpBrasilValidationResult
{
    /// <summary>Indicates whether the certificate chain is valid and trusted.</summary>
    public bool IsChainValid { get; init; }
    /// <summary>Indicates whether the certificate is issued by ICP-Brasil.</summary>
    public bool IsIcpBrasilCertificate { get; init; }
    /// <summary>Not set by the chain validator; always <see langword="null"/>.</summary>
    /// <remarks>
    /// Signature policies belong to the signature, not the certificate. Read the signature's
    /// policy OID and pass it to <see cref="IcpBrasilPolicyInfo.TryParse"/>.
    /// </remarks>
    [Obsolete("Signature policies are not certificate attributes. Use IcpBrasilPolicyInfo.TryParse with the signature's policy OID.")]
    public IcpBrasilPolicy? DetectedPolicy { get; init; }
    /// <summary>Certificate type (A1–A4 signature, S1–S4 confidentiality, T3/T4 timestamp, A CF-e-SAT, OM-BR).</summary>
    public IcpBrasilCertificateLevel? CertificateLevel { get; init; }
    /// <summary>CPF extracted from the SAN field (OID 2.16.76.1.3.1), if present (11 digits, no formatting).</summary>
    public string? Cpf { get; init; }
    /// <summary>CNPJ extracted from the SAN field (OID 2.16.76.1.3.3), if present (14 digits, no formatting).</summary>
    public string? Cnpj { get; init; }
    /// <summary>Formatted CPF as XXX.XXX.XXX-XX, or null if not available.</summary>
    public string? CpfFormatted => Cpf?.Length == 11
        ? $"{Cpf[..3]}.{Cpf[3..6]}.{Cpf[6..9]}-{Cpf[9..]}"
        : Cpf;
    /// <summary>Formatted CNPJ as XX.XXX.XXX/XXXX-XX, or null if not available.</summary>
    public string? CnpjFormatted => Cnpj?.Length == 14
        ? $"{Cnpj[..2]}.{Cnpj[2..5]}.{Cnpj[5..8]}/{Cnpj[8..12]}-{Cnpj[12..]}"
        : Cnpj;
    /// <summary>
    /// Professional registrations (OAB, CFM, CFF, CFO…) from the SubjectAltName arc
    /// 2.16.76.1.4.2.{council}. Empty when the certificate carries none.
    /// </summary>
    public IReadOnlyList<ProfessionalRegistration> ProfessionalRegistrations { get; init; } = [];
    /// <summary>Holder data from the SubjectAltName (PF/PJ fields, responsible person, registrations).</summary>
    public IcpBrasilCertificateData? CertificateData { get; init; }
    /// <summary>The time the chain was validated at (the signature timestamp time, or the time of validation).</summary>
    public DateTimeOffset ValidationTime { get; init; }
    /// <summary>The revocation status of the certificate and its CAs at <see cref="ValidationTime"/>.</summary>
    public SimpleSign.Core.Extensions.ChainRevocationStatus RevocationStatus { get; init; }
    /// <summary>Certificate chain elements with individual validation results.</summary>
    public IReadOnlyList<IcpBrasilChainElement> ChainElements { get; init; } = [];
    /// <summary>Bundled AC Raiz (root CA) certificates used for chain building.</summary>
    public IReadOnlyList<X509Certificate2> AcRaizCertificates { get; init; } = [];
    /// <summary>Validation errors found during chain validation.</summary>
    public IReadOnlyList<string> Errors { get; init; } = [];
    /// <summary>Non-blocking warnings found during chain validation.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = [];

    /// <summary>Indicates whether the overall validation passed (chain valid and no errors).</summary>
    public bool IsValid => IsChainValid && Errors.Count == 0;
}
