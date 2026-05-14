namespace SimpleSign.PAdES.Validation;

/// <summary>
/// Result of validating a single item in a batch.
/// </summary>
public sealed class BatchValidationResult
{
    /// <summary>Zero-based index of the item in the batch.</summary>
    public required int Index { get; init; }

    /// <summary>Optional identifier (e.g., file name) for the item.</summary>
    public string? Identifier { get; init; }

    /// <summary>Validation results for all signatures in this PDF. Null if the PDF could not be read.</summary>
    public IReadOnlyList<SignatureValidationResult>? Results { get; init; }

    /// <summary>Error message if the PDF could not be read or validated at all.</summary>
    public string? Error { get; init; }

    /// <summary>Whether the PDF was successfully processed (even if signatures are invalid).</summary>
    public bool IsProcessed => Error is null;

    /// <summary>Time taken to validate this item.</summary>
    public TimeSpan Duration { get; init; }
}
