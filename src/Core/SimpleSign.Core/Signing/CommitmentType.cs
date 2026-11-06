namespace SimpleSign.Core.Signing;

/// <summary>
/// CAdES/XAdES commitment type indication (RFC 5126 §5.11.1).
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
    /// Proof of receipt — the signer acknowledges receipt of the document.
    /// OID: 1.2.840.113549.1.9.16.6.2
    /// </summary>
    ProofOfReceipt,

    /// <summary>
    /// Proof of delivery — the signer confirms delivery of the document.
    /// OID: 1.2.840.113549.1.9.16.6.3
    /// </summary>
    ProofOfDelivery,

    /// <summary>
    /// Proof of sender — the signer confirms being the sender.
    /// OID: 1.2.840.113549.1.9.16.6.4
    /// </summary>
    ProofOfSender,

    /// <summary>
    /// Proof of approval — the signer approves the document content.
    /// OID: 1.2.840.113549.1.9.16.6.5
    /// </summary>
    ProofOfApproval,

    /// <summary>
    /// Proof of creation — the signer confirms creation of the document.
    /// OID: 1.2.840.113549.1.9.16.6.6
    /// </summary>
    ProofOfCreation,
}
