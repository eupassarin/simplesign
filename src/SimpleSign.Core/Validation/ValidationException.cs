using System.Diagnostics.CodeAnalysis;

namespace SimpleSign.Core.Validation;

/// <summary>
/// Thrown when the PDF validation engine encounters a structural
/// or cryptographic error that prevents validation from completing.
/// </summary>
[ExcludeFromCodeCoverage]
public class ValidationException : SimpleSignException
{
    /// <summary>Creates a new instance with the specified message.</summary>
    public ValidationException(string message) : base(message) { }
    /// <summary>Creates a new instance with the specified message and inner exception.</summary>
    public ValidationException(string message, Exception innerException) : base(message, innerException) { }
}
