namespace SimpleSign.Peru.Iofe.Accredited;

/// <summary>The format of a signed document.</summary>
public enum IofeDocumentFormat
{
    /// <summary>A PDF with PAdES signatures.</summary>
    Pdf = 0,

    /// <summary>A CMS signature (CAdES), with or without its content.</summary>
    Cms = 1,

    /// <summary>An XML document with XAdES signatures.</summary>
    Xml = 2,
}
