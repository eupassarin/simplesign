namespace SimpleSign.CAdES;

/// <summary>The validation of one signer (or countersigner) of a CAdES signature.</summary>
public sealed class CadesSignerValidationResult
{
    /// <summary>Position of the signer among its siblings (SignerInfo order, or countersignature order).</summary>
    public int Index { get; init; }

    /// <summary>The validation of this signer.</summary>
    public required CadesValidationResult Result { get; init; }

    /// <summary>The countersignatures of this signer, each validated against this signer's signature value.</summary>
    public IReadOnlyList<CadesSignerValidationResult> CounterSignatures { get; init; } = [];

    /// <summary>Whether this signer and all its countersigners have a valid signature, content digest and chain.</summary>
    public bool IsValid =>
        Result.Errors.Count == 0 && Result.IsSignatureValid && Result.IsIntegrityValid && Result.IsCertificateChainValid
        && CounterSignatures.All(c => c.IsValid);
}

/// <summary>The validation of every signer of a CAdES signature (<see cref="CadesSignatureValidator.ValidateAll"/>).</summary>
public sealed class CadesValidationReport
{
    /// <summary>The signers, in SignerInfo order.</summary>
    public IReadOnlyList<CadesSignerValidationResult> Signers { get; init; } = [];

    /// <summary>Errors that prevented validation (unparseable CMS, detached signature without data).</summary>
    public IReadOnlyList<string> Errors { get; init; } = [];

    /// <summary>Whether there is at least one signer and every signer and countersigner is valid.</summary>
    public bool IsValid => Errors.Count == 0 && Signers.Count > 0 && Signers.All(s => s.IsValid);
}
