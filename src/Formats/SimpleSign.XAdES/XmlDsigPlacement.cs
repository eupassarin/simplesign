namespace SimpleSign.XAdES;

/// <summary>Where a plain XML-DSig signature (<see cref="XmlDsigSigner"/>) is inserted.</summary>
public enum XmlDsigPlacement
{
    /// <summary>
    /// Right after the signed element, as its sibling (NF-e: <c>&lt;NFe&gt;&lt;infNFe/&gt;&lt;Signature/&gt;&lt;/NFe&gt;</c>).
    /// A signature of the whole document always goes at the end of the root.
    /// </summary>
    AfterSignedElement,

    /// <summary>As the last child of the document element (eSocial, EFD-Reinf).</summary>
    LastChildOfRoot,
}
