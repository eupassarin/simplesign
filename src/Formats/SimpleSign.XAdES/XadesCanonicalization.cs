namespace SimpleSign.XAdES;

/// <summary>
/// The XML canonicalization of SignedInfo and of the signed references
/// (W3C XMLDSig Core 1.1 §4.4.1 and §6.5). Both choices leave comments out.
/// </summary>
public enum XadesCanonicalization
{
    /// <summary>
    /// Exclusive XML Canonicalization 1.0 (<c>http://www.w3.org/2001/10/xml-exc-c14n#</c>): the
    /// signed parts do not depend on the namespaces of the surrounding document. The default.
    /// </summary>
    Exclusive,

    /// <summary>
    /// Canonical XML 1.0 (<c>http://www.w3.org/TR/2001/REC-xml-c14n-20010315</c>): the signed
    /// parts carry the namespace declarations in scope around them, as some profiles require.
    /// </summary>
    Inclusive,
}
