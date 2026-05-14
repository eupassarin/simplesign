using SimpleSign.Core;

namespace SimpleSign.Pdf.Exceptions;

/// <summary>
/// Thrown when a PDF file has a structural problem that prevents parsing — for example,
/// a malformed cross-reference table, missing trailer, or invalid startxref offset.
/// </summary>
public sealed class PdfStructureException : SimpleSignException
{
    /// <summary>Byte offset within the PDF where the structural error was detected, if known.</summary>
    public long? ByteOffset { get; }

    /// <summary>Creates a new instance with no message.</summary>
    public PdfStructureException() : base("PDF structure is invalid.") { }

    /// <summary>Creates a new instance with the specified message.</summary>
    public PdfStructureException(string message) : base(message) { }

    /// <summary>Creates a new instance with the specified message and inner exception.</summary>
    public PdfStructureException(string message, Exception innerException) : base(message, innerException) { }

    /// <summary>
    /// Creates a new instance with the specified message and byte offset.
    /// </summary>
    /// <param name="message">A description of the structural problem.</param>
    /// <param name="byteOffset">Byte offset in the PDF where the error was detected.</param>
    public PdfStructureException(string message, long? byteOffset)
        : base(message)
    {
        ByteOffset = byteOffset;
    }

    /// <summary>
    /// Creates a new instance with the specified message, inner exception, and byte offset.
    /// </summary>
    public PdfStructureException(string message, Exception innerException, long? byteOffset)
        : base(message, innerException)
    {
        ByteOffset = byteOffset;
    }
}
