namespace SimpleSign.Core.Policies;

/// <summary>
/// Finds the document of a signature policy (EN 319 102-1 §5.2.4): the file a signature's signature-policy-identifier
/// names, when the signature does not carry it in a signature-policy-store. Set it on
/// <see cref="Validation.ValidationOptions.SignaturePolicyDocuments"/>; without one, a policy document is available only
/// when the signature carries it, and the <c>PolicyAvailable</c> constraint of the validation policy decides what that
/// means (the default only informs).
/// </summary>
public interface ISignaturePolicyDocumentProvider
{
    /// <summary>The policy document of <paramref name="policyOid"/>, or null when it is not known.</summary>
    /// <param name="policyOid">The OID the signature's signature-policy-identifier names.</param>
    /// <returns>The document's bytes, or null.</returns>
    byte[]? Find(string policyOid);
}
