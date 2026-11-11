using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Localization;

namespace SimpleSign.TestBench.Signing;

/// <summary>Whether an option (or one value of it) is shown, and if it cannot be chosen, why.</summary>
public sealed record OptionState(bool Visible, string? Disabled = null, string? Note = null)
{
    public static readonly OptionState Shown = new(true);
    public static readonly OptionState Hidden = new(false);

    public static OptionState Off(string reason) => new(true, reason);
}

public enum IssueSeverity
{
    Info,
    Warning,
    Error,
}

/// <summary>A problem with the current combination, attached to the step that can fix it.</summary>
public sealed record OptionIssue(IssueSeverity Severity, string Step, string Message)
{
    /// <summary>
    /// Whether the issue only foresees that the signing policy refuses the signer (the library would throw a
    /// SigningException): with <c>attemptRefused</c> the run goes on, so the refusal itself is shown.
    /// </summary>
    public bool IsPolicyRefusal => Severity == IssueSeverity.Error && Step == "signer" && Message.Contains("SigningException", StringComparison.Ordinal);

    /// <summary>Whether <paramref name="issues"/> stop a run: any error, except foreseen policy refusals when <paramref name="attemptRefused"/>.</summary>
    public static bool Block(IEnumerable<OptionIssue> issues, bool attemptRefused) =>
        issues.Any(i => i.Severity == IssueSeverity.Error && !(attemptRefused && i.IsPolicyRefusal));
}

/// <summary>
/// The result of the rules: the state of every option key, the issues of the current selection,
/// and the effective options (the selection with forced values applied) that the runner uses.
/// </summary>
public sealed record OptionsReport(
    IReadOnlyDictionary<string, OptionState> Options,
    IReadOnlyList<OptionIssue> Issues,
    SigningOptions Effective,
    string EffectiveLevel)
{
    public bool CanSign => Issues.All(i => i.Severity != IssueSeverity.Error);

    /// <summary>Whether the run may go on: <see cref="CanSign"/>, or only foreseen policy refusals when the options ask to attempt them.</summary>
    public bool CanRun => !OptionIssue.Block(Issues, Effective.AttemptRefused);
}

/// <summary>
/// The single source of truth for which options combine. Every rule mirrors a library constraint
/// (or a standard the library follows) and says why, so the UI never shows an incompatible
/// combination and the run matrix only generates valid ones.
/// </summary>
public static class Compatibility
{
    public const string StepDocument = "document";
    public const string StepSigner = "signer";
    public const string StepType = "type";
    public const string StepCrypto = "crypto";
    public const string StepField = "field";
    public const string StepDetails = "details";
    public const string StepMode = "mode";

    /// <summary>Applies every rule to <paramref name="options"/>.</summary>
    /// <param name="options">The user's selection.</param>
    /// <param name="document">Facts of the chosen document (null: none chosen yet).</param>
    /// <param name="credential">Facts of the chosen credential (null: none chosen yet).</param>
    /// <param name="sandboxConnected">Whether a Sandbox is connected (its TSAs can be chosen).</param>
    /// <param name="signingPolicy">The signing policy the signer is checked against (null: the library's default).</param>
    public static OptionsReport Evaluate(SigningOptions options, DocumentFacts? document, CredentialFacts? credential, bool sandboxConnected = true, SigningPolicyInput? signingPolicy = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        var state = new Dictionary<string, OptionState>(StringComparer.Ordinal);
        var issues = new List<OptionIssue>();
        var o = options;

        void Set(string key, OptionState value) => state[key] = value;
        void Error(string step, string message) => issues.Add(new(IssueSeverity.Error, step, message));
        void Warn(string step, string message) => issues.Add(new(IssueSeverity.Warning, step, message));
        void Info(string step, string message) => issues.Add(new(IssueSeverity.Info, step, message));

        // ── 1. Document ────────────────────────────────────────────────
        if (document is null)
        {
            Error(StepDocument, L.T("Choose a document to sign."));
        }
        else if (document.Error is not null)
        {
            Error(StepDocument, L.T("The file could not be read as a PDF: {0}", document.Error));
        }
        else
        {
            if (document.DocMdpLevel == 1)
            {
                Error(StepDocument, L.T("The document is certified with DocMDP P=1 (no changes allowed): any further signature would invalidate the certification (ISO 32000-1 §12.8.2.2.2)."));
            }

            if (document.IsEncrypted)
            {
                Error(StepDocument, L.T("Encrypted PDFs cannot be signed: decrypt the document first."));
            }
        }

        bool hasSignatures = document?.Signatures.Count > 0;
        bool hasEmptyFields = document?.EmptyFields.Count > 0;
        bool isPdfA = document?.IsPdfA == true;
        bool isPdfA1 = document?.IsPdfA1 == true;

        // ── 7. Mode (decided early: deferred and batch support fewer options) ─
        bool deferred = o.Mode == RunMode.Deferred;
        bool batch = o.Mode == RunMode.Batch;
        Set("mode.Sign", OptionState.Shown);
        Set("mode.Deferred", OptionState.Shown);
        Set("mode.Batch", OptionState.Shown);
        Set("batch", batch ? OptionState.Shown : OptionState.Hidden);
        if (batch && (o.BatchCopies < 1 || o.BatchCopies > 50))
        {
            Error(StepMode, L.T("Batch: between 1 and 50 copies."));
        }

        if (batch && (o.MaxConcurrency < 1 || o.MaxConcurrency > 16))
        {
            Error(StepMode, L.T("Batch: max concurrency between 1 and 16."));
        }

        string? policyUnsupported = deferred ? L.T("DeferredSigner has no signature policy option.")
            : batch ? L.T("BatchSigner has no signature policy option.") : null;

        // ── 3. Signature type ──────────────────────────────────────────
        bool pdfA1Preserved = isPdfA1 && o.PreservePdfA && !deferred && !batch;
        Set("kind.Baseline", OptionState.Shown);
        Set("kind.CustomPolicy", policyUnsupported is not null ? OptionState.Off(policyUnsupported) : OptionState.Shown);

        var kind = o.Kind;
        if (state[$"kind.{kind}"].Disabled is { } kindReason)
        {
            Error(StepType, kindReason);
        }

        string adbeOnly = L.T("PAdES B-T and above (ETSI EN 319 142-1) need the ETSI.CAdES.detached sub-filter; this document is PDF/A-1 with preservation on, which only allows adbe.pkcs7.detached.");
        foreach (var level in Enum.GetValues<BaselineLevel>())
        {
            Set($"level.{level}", level != BaselineLevel.BB && pdfA1Preserved ? OptionState.Off(adbeOnly)
                : level != BaselineLevel.BB && o.SubFilter == SubFilterChoice.AdbePkcs7Detached ? OptionState.Off(L.T("adbe.pkcs7.detached is a legacy (pre-PAdES) format: B-T and above need ETSI.CAdES.detached. Change the sub-filter in Cryptography."))
                : OptionState.Shown);
        }

        Set("customPolicy", kind == SignatureKind.CustomPolicy ? OptionState.Shown : OptionState.Hidden);
        if (kind == SignatureKind.CustomPolicy)
        {
            if (string.IsNullOrWhiteSpace(o.CustomPolicy.Oid) || !IsOid(o.CustomPolicy.Oid))
            {
                Error(StepType, L.T("Custom policy: enter a valid OID (e.g. 1.2.3.4.5)."));
            }

            if (!IsHex(o.CustomPolicy.HashHex))
            {
                Error(StepType, L.T("Custom policy: the policy hash must be hexadecimal (the digest of the policy document)."));
            }
        }

        // The effective level: what the library will be asked to produce.
        BaselineLevel effectiveLevel = pdfA1Preserved ? BaselineLevel.BB : o.Level;
        if (state[$"level.{o.Level}"].Disabled is { } levelReason)
        {
            Error(StepType, levelReason);
        }

        bool needsTsa = effectiveLevel != BaselineLevel.BB;
        bool needsArchive = effectiveLevel == BaselineLevel.BLTA;
        Set("timestamp", needsTsa ? OptionState.Shown : OptionState.Hidden);
        Set("archiveTimestamp", needsArchive ? OptionState.Shown : OptionState.Hidden);
        Set("revocationPreference", effectiveLevel >= BaselineLevel.BLT ? OptionState.Shown : OptionState.Hidden);
        Set("returnLowerLevel", !needsTsa ? OptionState.Hidden
            : o.Mode != RunMode.Sign ? OptionState.Off(L.T("Only SignWithDetailsAsync (Sign now) reports a lower achieved level; deferred and batch always throw."))
            : OptionState.Shown);
        SharedRules.TsaProviders(sandboxConnected, Set);
        if (needsTsa)
        {
            SharedRules.CheckTsa(o.Timestamp, L.T("Signature TSA"), state, Error, StepType);
            if (needsArchive && o.SeparateArchiveTsa)
            {
                SharedRules.CheckTsa(o.ArchiveTimestamp, L.T("Archive TSA"), state, Error, StepType);
            }
        }

        // ── 4. Cryptography ────────────────────────────────────────────
        var effective = o with { Padding = SharedRules.Crypto(o.Hash, o.Padding, credential, state, Error, StepCrypto) };

        Set("subFilter", OptionState.Shown);
        Set("subFilter.EtsiCadesDetached", pdfA1Preserved ? OptionState.Off(L.T("PDF/A-1 (ISO 19005-1) only allows adbe.pkcs7.detached signatures."))
            : OptionState.Shown);
        Set("subFilter.AdbePkcs7Detached", o.Level != BaselineLevel.BB ? OptionState.Off(L.T("Legacy PKCS#7: only for B-B. B-T and above need ETSI.CAdES.detached."))
            : OptionState.Shown);
        effective = effective with
        {
            SubFilter = pdfA1Preserved ? SubFilterChoice.AdbePkcs7Detached : o.SubFilter,
            Level = effectiveLevel,
        };

        Set("pdfa", !isPdfA ? new OptionState(false, Note: L.T("The document is not PDF/A."))
            : deferred || batch ? OptionState.Off(L.T("WithPdfAPreservation is a PadesSignerBuilder option (Sign now only)."))
            : OptionState.Shown);
        if (isPdfA && !o.PreservePdfA && !deferred && !batch)
        {
            Info(StepCrypto, L.T("This is a PDF/A document: turn on PDF/A preservation to have the library refuse options that would break conformance."));
        }

        Set("contents", OptionState.Shown);
        if (o.ContentsReservedBytes is { } reserved && (reserved < 4096 || reserved > 200_000))
        {
            Error(StepCrypto, L.T("Reserved /Contents size must be between 4096 and 200000 bytes."));
        }

        // ── 5. Field and appearance ────────────────────────────────────
        Set("field.New", OptionState.Shown);
        Set("field.Existing", !hasEmptyFields ? new OptionState(false, Note: L.T("The document has no empty signature field.")) : OptionState.Shown);
        bool existing = o.FieldMode == FieldMode.Existing && hasEmptyFields;
        if (o.FieldMode == FieldMode.Existing && !hasEmptyFields)
        {
            Error(StepField, L.T("The document has no empty signature field: choose New field."));
        }

        if (existing && (o.ExistingFieldName is null || document?.EmptyFields.Contains(o.ExistingFieldName) != true))
        {
            Error(StepField, L.T("Choose which empty field to sign."));
        }

        Set("fieldName", existing ? OptionState.Hidden : OptionState.Shown);
        if (!existing && (string.IsNullOrWhiteSpace(o.FieldName) || o.FieldName.Contains('.', StringComparison.Ordinal)))
        {
            Error(StepField, L.T("The field name is required and cannot contain '.' (it separates names in a field hierarchy)."));
        }

        if (!existing && document?.Signatures.Any(s => s.FieldName == o.FieldName) == true)
        {
            Error(StepField, L.T("The document already has a signature field named '{0}'.", o.FieldName));
        }

        Set("appearance", OptionState.Shown);
        Set("appearance.placement", existing ? new OptionState(false, Note: L.T("The stamp is drawn in the existing field's rectangle.")) : OptionState.Shown);
        Set("appearance.image", OptionState.Shown);
        if (o.Appearance.Visible && !existing && !o.Appearance.AutoPosition && (o.Appearance.Width is <= 0 || o.Appearance.Height is <= 0))
        {
            Error(StepField, L.T("The stamp needs a positive width and height."));
        }

        // ── 6. Details ─────────────────────────────────────────────────
        string? builderOnly = deferred ? L.T("DeferredSigner only takes SignatureFieldOptions (reason, location, contact, signer name).")
            : batch ? L.T("BatchSigner only takes SignatureFieldOptions (reason, location, contact, signer name).") : null;
        Set("details.basic", OptionState.Shown);
        Set("details.signingTime", builderOnly is not null ? OptionState.Off(builderOnly) : OptionState.Shown);
        Set("details.signer", builderOnly is not null ? OptionState.Off(builderOnly) : OptionState.Shown);
        Set("metadata.policy", kind != SignatureKind.Baseline ? new OptionState(false, Note: L.T("The signature policy comes from the Signature type step.")) : OptionState.Shown);
        if (o.UseSignerDetails && builderOnly is null)
        {
            if (string.IsNullOrWhiteSpace(o.Metadata.SignerName))
            {
                Error(StepDetails, L.T("Signer metadata: the signer name is required."));
            }
        }

        string? docInfoReason = builderOnly ?? (existing ? L.T("The document information dictionary cannot be changed when signing an existing field.") : null);
        Set("documentInfo", docInfoReason is not null ? OptionState.Off(docInfoReason) : OptionState.Shown);
        foreach (var entry in o.DocumentInfo)
        {
            if (string.IsNullOrWhiteSpace(entry.Key) || entry.Key.Any(c => c <= ' ' || c > '~' || "()<>[]{}/%#".Contains(c, StringComparison.Ordinal)))
            {
                Error(StepDetails, L.T("Document info key '{0}' must be printable ASCII without PDF delimiters.", entry.Key));
            }
        }

        foreach (var level in Enum.GetValues<CertificationChoice>().Where(l => l != CertificationChoice.None))
        {
            Set($"certification.{level}", hasSignatures
                ? OptionState.Off(L.T("Only the first signature of a document can certify it (ISO 32000-1 §12.8.2.2); this document is already signed."))
                : OptionState.Shown);
        }

        Set("certification", OptionState.Shown);
        if (o.Certification != CertificationChoice.None && hasSignatures)
        {
            Error(StepDetails, L.T("The document is already signed: certification is no longer possible."));
        }

        Set("operationId", OptionState.Shown);

        // ── 2. Signer ──────────────────────────────────────────────────
        Set("signingPolicy", OptionState.Shown);
        SharedRules.Signer(credential, Error, Warn, StepSigner, signingPolicy);
        return new OptionsReport(state, issues, effective, LevelName(effective));
    }

    /// <summary>The level as shown to users (B-B, B-T, B-LT, B-LTA).</summary>
    public static string LevelName(SigningOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return options.Level switch
        {
            BaselineLevel.BB => "B-B",
            BaselineLevel.BT => "B-T",
            BaselineLevel.BLT => "B-LT",
            _ => "B-LTA",
        };
    }

    internal static bool IsOid(string value) =>
        value.Split('.') is { Length: >= 2 } parts && parts.All(p => p.Length > 0 && p.All(char.IsAsciiDigit));

    internal static bool IsHex(string? value) =>
        !string.IsNullOrEmpty(value) && value.Length % 2 == 0 && value.All(char.IsAsciiHexDigit);
}
