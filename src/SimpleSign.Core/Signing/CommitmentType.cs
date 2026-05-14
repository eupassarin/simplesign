namespace SimpleSign.Core.Signing;

/// <summary>
/// CAdES commitment type indication (RFC 5126 §5.11.1).
/// Indicates the type of commitment assumed by the signer.
/// </summary>
public enum CommitmentType
{
    /// <summary>
    /// Proof of origin — the signer is the author of the document.
    /// OID: 1.2.840.113549.1.9.16.6.1
    /// </summary>
    ProofOfOrigin,

    /// <summary>
    /// Proof of approval — the signer approves the document content.
    /// OID: 1.2.840.113549.1.9.16.6.5
    /// </summary>
    ProofOfApproval,
}
