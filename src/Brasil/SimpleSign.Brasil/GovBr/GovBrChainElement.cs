namespace SimpleSign.Brasil.GovBr;

/// <summary>Element of the Gov.br certificate chain.</summary>
public sealed class GovBrChainElement
{
    /// <summary>Certificate subject distinguished name.</summary>
    public string Subject { get; init; } = string.Empty;
    /// <summary>Certificate issuer distinguished name.</summary>
    public string Issuer { get; init; } = string.Empty;
    /// <summary>Certificate validity start date.</summary>
    public DateTime NotBefore { get; init; }
    /// <summary>Certificate validity end date.</summary>
    public DateTime NotAfter { get; init; }
    /// <summary>Certificate SHA-1 thumbprint (hex).</summary>
    public string Thumbprint { get; init; } = string.Empty;
    /// <summary>Validation errors for this chain element.</summary>
    public IReadOnlyList<string> Errors { get; init; } = [];
    /// <summary>Non-blocking validation warnings for this chain element.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = [];
}
