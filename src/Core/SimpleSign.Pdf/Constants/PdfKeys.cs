namespace SimpleSign.Pdf.Constants;

internal static class PdfKeys
{
    /// <summary>PDF /AcroForm dictionary key for interactive forms.</summary>
    public const string AcroForm = "/AcroForm";
    /// <summary>PDF /Annots key for page annotations.</summary>
    public const string Annots = "/Annots";
    /// <summary>PDF /ByteRange key defining the signed byte range in a signature field.</summary>
    public const string ByteRange = "/ByteRange";
    /// <summary>PDF /Fields key listing form field entries.</summary>
    public const string Fields = "/Fields";
    /// <summary>PDF /Filter key specifying stream decoding filters.</summary>
    public const string Filter = "/Filter";
    /// <summary>PDF /FT/Sig key (with space) for signature field type.</summary>
    public const string FtSig = "/FT /Sig";
    /// <summary>PDF /FT/Sig key (no space) for signature field type.</summary>
    public const string FtSigNoSpace = "/FT/Sig";
    /// <summary>PDF /Kids key for child objects in a page tree or field hierarchy.</summary>
    public const string Kids = "/Kids";
    /// <summary>PDF /Length key for stream byte length.</summary>
    public const string Length = "/Length";
    /// <summary>PDF /Perms key for permissions dictionary in encrypted documents.</summary>
    public const string Perms = "/Perms";
    /// <summary>PDF /Prev key for cross-reference offset in incremental updates.</summary>
    public const string Prev = "/Prev";
    /// <summary>PDF /Rect key for annotation rectangle coordinates.</summary>
    public const string Rect = "/Rect";
    /// <summary>PDF /SigFlags key for signature field flags in the AcroForm dictionary.</summary>
    public const string SigFlags = "/SigFlags";
    /// <summary>PDF /Type key for object type identifier.</summary>
    public const string Type = "/Type";
    /// <summary>PDF /Type/Sig key (with space) for signature object type.</summary>
    public const string TypeSig = "/Type /Sig";
    /// <summary>PDF /Type/Sig key (no space) for signature object type.</summary>
    public const string TypeSigNoSpace = "/Type/Sig";
}
