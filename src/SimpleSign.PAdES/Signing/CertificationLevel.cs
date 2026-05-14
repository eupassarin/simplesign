namespace SimpleSign.PAdES.Signing;

/// <summary>
/// Certification level for DocMDP (Document Modification Detection and Prevention) signatures.
/// Controls what modifications are allowed after the document is certified.
/// </summary>
public enum CertificationLevel
{
    /// <summary>No changes allowed. The document is fully locked after certification.</summary>
    NoChanges = 1,

    /// <summary>Only form filling is allowed after certification.</summary>
    FormFilling = 2,

    /// <summary>Form filling and annotations (comments) are allowed after certification.</summary>
    FormFillingAndAnnotations = 3
}
