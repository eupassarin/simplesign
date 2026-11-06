using SimpleSign.Core.Signing;

namespace SimpleSign.Brasil.Signing;

/// <summary>
/// Metadata for an Advanced Electronic Signature (AEA) per Lei 14.063/2020.
/// The organization issues its own X.509 certificates and uses SimpleSign to embed
/// CAdES attributes (commitment-type-indication, signature-policy-identifier) and
/// a visual seal identifying the signature as AEA.
/// </summary>
public sealed class AdvancedSignatureInfo
{
    /// <summary>Full name of the signer (e.g., "André Almeida").</summary>
    public required string SignerName { get; init; }

    /// <summary>
    /// CPF of the signer (11 digits, no punctuation).
    /// Will be masked in the visual seal: "12345678901" → "***.456.789-**".
    /// </summary>
    public required string Cpf { get; init; }

    /// <summary>Authentication method used to identify the signer.</summary>
    public required AuthenticationMethod AuthMethod { get; init; }

    /// <summary>E-mail address of the signer.</summary>
    public string? Email { get; init; }

    /// <summary>IP address of the signer at the time of signing.</summary>
    public string? IpAddress { get; init; }

    /// <summary>
    /// CAdES commitment type. Default: <see cref="CommitmentType.ProofOfApproval"/>.
    /// </summary>
    public CommitmentType CommitmentType { get; init; } = CommitmentType.ProofOfApproval;

    /// <summary>Name of the issuing institution (e.g., "TCE-ES").</summary>
    public string? InstitutionName { get; init; }

    /// <summary>CNPJ of the issuing institution (14 digits).</summary>
    public string? InstitutionCnpj { get; init; }

    /// <summary>
    /// OID of the signature policy. When null, no signature-policy-identifier attribute is added.
    /// Organizations can define their own policy OIDs.
    /// </summary>
    public string? PolicyOid { get; init; }

    /// <summary>URI of the signature policy document.</summary>
    public string? PolicyUri { get; init; }

    /// <summary>
    /// Masks a CPF for display: "12345678901" → "***.456.789-**".
    /// Shows only the 6 central digits for privacy.
    /// </summary>
    public static string MaskCpf(string cpf)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cpf);

        // Strip non-digits and validate count
        Span<char> digits = stackalloc char[12]; // extra slot for overflow detection
        int count = 0;
        foreach (char c in cpf)
        {
            if (char.IsDigit(c))
            {
                if (count < 12)
                {
                    digits[count] = c;
                }
                count++;
            }
        }

        if (count != 11)
        {
            throw new ArgumentException("CPF must contain exactly 11 digits.", nameof(cpf));
        }

        return $"***.{digits[3]}{digits[4]}{digits[5]}.{digits[6]}{digits[7]}{digits[8]}-**";
    }
}
