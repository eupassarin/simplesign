using SimpleSign.Core.Signing;

namespace SimpleSign.Peru.Iofe.Accredited;

/// <summary>A document signed under the accredited configuration.</summary>
/// <param name="Document">The signed document.</param>
/// <param name="Format">Its format.</param>
/// <param name="Level">The level the signature reached (B-B without a time-stamp authority, B-LT with one).</param>
/// <param name="Timestamped">Whether it carries a time-stamp of the agent's authority, checked as section 4.4 asks.</param>
/// <param name="OperationId">The identifier written to the audit record.</param>
/// <param name="SignerSubject">The subject of the signing certificate.</param>
/// <param name="SignerCertificateSha256">The SHA-256 of the signing certificate, upper-case hex.</param>
/// <param name="PolicyName">The signing policy the signature was made under.</param>
/// <param name="UnderContingency">Whether it was made under a declared contingency.</param>
/// <param name="KeySource">Where the key that signed it is kept: the organization's module or a remote signing service.</param>
public sealed record IofeSignedDocument(
    byte[] Document,
    IofeDocumentFormat Format,
    AdesBaselineLevel Level,
    bool Timestamped,
    string OperationId,
    string SignerSubject,
    string SignerCertificateSha256,
    string PolicyName,
    bool UnderContingency,
    IofeKeySourceKind KeySource = IofeKeySourceKind.Module);
