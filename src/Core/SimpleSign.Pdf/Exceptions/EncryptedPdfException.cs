using SimpleSign.Core;

namespace SimpleSign.Pdf.Exceptions;

/// <summary>
/// Thrown when attempting to sign or validate an encrypted PDF.
/// SimpleSign does not support encrypted PDFs — decrypt first using Adobe Acrobat or qpdf.
/// </summary>
public sealed class EncryptedPdfException : SimpleSignException
{
    /// <summary>Creates a new instance with the specified message.</summary>
    public EncryptedPdfException(string message) : base(message) { }

    /// <summary>Creates a new instance with the specified message and inner exception.</summary>
    public EncryptedPdfException(string message, Exception innerException) : base(message, innerException) { }
}
