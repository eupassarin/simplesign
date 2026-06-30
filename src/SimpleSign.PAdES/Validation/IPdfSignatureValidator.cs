using SimpleSign.Core.Validation;

namespace SimpleSign.PAdES.Validation;

/// <summary>PAdES signature validation engine.</summary>
public interface IPdfSignatureValidator
{
    /// <summary>Validates all signature fields in a PDF stream.</summary>
    Task<IReadOnlyList<SignatureValidationResult>> ValidateAsync(Stream pdfStream, string? operationId = null, CancellationToken cancellationToken = default);

    /// <summary>Validates a single signature field by name.</summary>
    Task<SignatureValidationResult?> ValidateFieldAsync(Stream pdfStream, string fieldName, CancellationToken cancellationToken = default);

    /// <summary>Validates multiple PDF streams in parallel.</summary>
    Task<IReadOnlyList<BatchValidationResult>> ValidateBatchAsync(IEnumerable<(Stream Stream, string? Identifier)> items, int maxConcurrency = 4, string? operationId = null, CancellationToken cancellationToken = default);
}
