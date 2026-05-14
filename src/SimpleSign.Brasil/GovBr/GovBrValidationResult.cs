namespace SimpleSign.Brasil.GovBr;

/// <summary>Gov.br chain validation result.</summary>
public sealed class GovBrValidationResult
{
    /// <summary>Indicates whether the certificate chain is valid and trusted.</summary>
    public bool IsChainValid { get; init; }
    /// <summary>Indicates whether the certificate is a Gov.br certificate.</summary>
    public bool IsGovBrCertificate { get; init; }
    /// <summary>Gov.br assurance level (Bronze, Silver, Gold, or Platinum).</summary>
    public GovBrAssuranceLevel? AssuranceLevel { get; init; }

    /// <summary>CPF extracted from the SAN field (OID 2.16.76.1.3.1), if available.</summary>
    public string? Cpf { get; init; }

    /// <summary>Certificate chain elements with individual validation results.</summary>
    public IReadOnlyList<GovBrChainElement> ChainElements { get; init; } = [];
    /// <summary>Validation errors found during chain validation.</summary>
    public IReadOnlyList<string> Errors { get; init; } = [];
    /// <summary>Non-blocking warnings found during chain validation.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = [];

    /// <summary>Indicates whether the overall validation passed (chain valid and no errors).</summary>
    public bool IsValid => IsChainValid && Errors.Count == 0;

    /// <summary>Formatted CPF as XXX.XXX.XXX-XX, or null if not available.</summary>
    public string? CpfFormatted => Cpf?.Length == 11
        ? $"{Cpf[..3]}.{Cpf[3..6]}.{Cpf[6..9]}-{Cpf[9..]}"
        : Cpf;
}
