using SimpleSign.Core.Policies;

namespace SimpleSign.Brazil.GovBr;

/// <summary>
/// SimpleSign's validation policy for signatures made on Gov.br (advanced electronic signature, Lei 14.063/2020),
/// derived from SimpleSign's default policy. There is no signing policy: a Gov.br signature is made by Gov.br's own
/// service. Write it out with <c>ToJson()</c> to keep it as a file.
/// </summary>
public static class GovBrPolicies
{
    private static readonly PolicyConstraint Fail = new(ConstraintLevel.Fail);

    /// <summary>
    /// Validation: the constraints of <see cref="ValidationPolicy.Default"/>, and a signing certificate without
    /// digitalSignature or nonRepudiation fails. Validate with <see cref="GovBrExtension"/>, whose roots and chain
    /// validation the policy relies on.
    /// </summary>
    public static ValidationPolicy Validation { get; } = ValidationPolicy.Default
        .WithName("Gov.br")
        .With("SignatureConstraints/BasicSignatureConstraints/SigningCertificate/KeyUsage",
            Fail with { Ids = ["digitalSignature", "nonRepudiation"] });
}
