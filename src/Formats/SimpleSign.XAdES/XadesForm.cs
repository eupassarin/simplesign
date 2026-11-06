namespace SimpleSign.XAdES;

/// <summary>XAdES signature packaging form.</summary>
public enum XadesForm
{
    /// <summary>Signature is embedded as a child of the signed XML document's root element.</summary>
    Enveloped = 0,

    /// <summary>Signature is in a separate file; the original document is referenced by URI.</summary>
    Detached = 1,

    /// <summary>The signed data is wrapped inside the Signature element as an Object.</summary>
    Enveloping = 2
}
