namespace SimpleSign.Core.Validation;

/// <summary>The outcome of one check of a validation.</summary>
public enum ConstraintStatus
{
    /// <summary>The check passed.</summary>
    Passed,

    /// <summary>The check failed, and the policy reports it as a warning only.</summary>
    Warning,

    /// <summary>The check failed and determines the result.</summary>
    Failed,

    /// <summary>The check could not be completed (missing evidence, network failure).</summary>
    Indeterminate,

    /// <summary>The check was not run: disabled by the options, or a constraint of the policy SimpleSign does not evaluate.</summary>
    NotChecked,

    /// <summary>The check failed, and the policy records it for information only (INFORM).</summary>
    Information,
}

/// <summary>One check of a signature validation, in the terms of ETSI EN 319 102-1.</summary>
/// <param name="Id">A stable identifier of the check, the path of the policy constraint, such as <c>SignatureConstraints/BasicSignatureConstraints/SigningCertificate/KeyUsage</c>.</param>
/// <param name="Status">The outcome.</param>
/// <param name="SubIndication">The ETSI sub-indication a failure leads to, or null.</param>
/// <param name="Message">A sentence on what was found.</param>
public sealed record ValidationConstraintResult(
    string Id,
    ConstraintStatus Status,
    SignatureSubIndication? SubIndication,
    string Message);
