using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Localization;
using SimpleSign.TestBench.Sandbox;

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
public sealed record OptionIssue(IssueSeverity Severity, string Step, string Message);

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
    public static OptionsReport Evaluate(SigningOptions options, DocumentFacts? document, CredentialFacts? credential)
    {
        ArgumentNullException.ThrowIfNull(options);
        var state = new Dictionary<string, OptionState>(StringComparer.Ordinal);
        var issues = new List<OptionIssue>();
        var o = options;
        bool sandbox = o.Environment == EnvironmentMode.Sandbox;

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

        if (batch && credential?.Kind == CredentialKind.Psc)
        {
            Info(StepMode, L.T("PSC tokens with the single_signature scope are spent after one document; use signature_session for batches."));
        }

        string? policyUnsupported = deferred ? L.T("DeferredSigner has no signature policy option.")
            : batch ? L.T("BatchSigner has no signature policy option.") : null;

        // ── 3. Signature type ──────────────────────────────────────────
        bool pdfA1Preserved = isPdfA1 && o.PreservePdfA && !deferred && !batch;
        Set("kind.Baseline", OptionState.Shown);
        Set("kind.IcpBrasil", policyUnsupported is not null ? OptionState.Off(policyUnsupported)
            : pdfA1Preserved ? OptionState.Off(L.T("ICP-Brasil policies require the PBAD.PAdES sub-filter, which PDF/A-1 does not allow. Turn off PDF/A preservation or use a PDF/A-2 document."))
            : OptionState.Shown);
        Set("kind.CustomPolicy", policyUnsupported is not null ? OptionState.Off(policyUnsupported) : OptionState.Shown);

        var kind = o.Kind;
        if (state[$"kind.{kind}"].Disabled is { } kindReason)
        {
            Error(StepType, kindReason);
        }

        bool icp = kind == SignatureKind.IcpBrasil;
        string adbeOnly = L.T("PAdES B-T and above (ETSI EN 319 142-1) need the ETSI.CAdES.detached sub-filter; this document is PDF/A-1 with preservation on, which only allows adbe.pkcs7.detached.");
        foreach (var level in Enum.GetValues<BaselineLevel>())
        {
            Set($"level.{level}", icp ? OptionState.Hidden
                : level != BaselineLevel.BB && pdfA1Preserved ? OptionState.Off(adbeOnly)
                : level != BaselineLevel.BB && o.SubFilter == SubFilterChoice.AdbePkcs7Detached ? OptionState.Off(L.T("adbe.pkcs7.detached is a legacy (pre-PAdES) format: B-T and above need ETSI.CAdES.detached. Change the sub-filter in Cryptography."))
                : OptionState.Shown);
        }

        Set("icp.policy", icp ? OptionState.Shown : OptionState.Hidden);
        Set("icp.version", icp ? OptionState.Shown : OptionState.Hidden);
        Set("icp.adrbTimestamp", icp && o.IcpPolicy == IcpPolicyKind.AdRb ? OptionState.Shown : OptionState.Hidden);
        Set("customPolicy", kind == SignatureKind.CustomPolicy ? OptionState.Shown : OptionState.Hidden);
        if (kind == SignatureKind.CustomPolicy)
        {
            if (string.IsNullOrWhiteSpace(o.CustomPolicy.Oid) || !IsOid(o.CustomPolicy.Oid))
            {
                Error(StepType, L.T("Custom policy: enter a valid OID (e.g. 2.16.76.1.7.1.11.1.3)."));
            }

            if (!IsHex(o.CustomPolicy.HashHex))
            {
                Error(StepType, L.T("Custom policy: the policy hash must be hexadecimal (the digest of the policy document)."));
            }
        }

        // The effective level: what the library will be asked to produce.
        BaselineLevel effectiveLevel = icp
            ? o.IcpPolicy switch
            {
                IcpPolicyKind.AdRb => o.IcpAdRbTimestamp ? BaselineLevel.BT : BaselineLevel.BB,
                IcpPolicyKind.AdRt => BaselineLevel.BT,
                _ => BaselineLevel.BLTA,
            }
            : pdfA1Preserved ? BaselineLevel.BB : o.Level;
        if (!icp && state[$"level.{o.Level}"].Disabled is { } levelReason)
        {
            Error(StepType, levelReason);
        }

        bool needsTsa = effectiveLevel != BaselineLevel.BB;
        bool needsArchive = effectiveLevel == BaselineLevel.BLTA;
        Set("timestamp", needsTsa ? OptionState.Shown : OptionState.Hidden);
        Set("archiveTimestamp", needsArchive ? OptionState.Shown : OptionState.Hidden);
        Set("returnLowerLevel", !needsTsa || icp ? OptionState.Hidden
            : o.Mode != RunMode.Sign ? OptionState.Off(L.T("Only SignWithDetailsAsync (Sign now) reports a lower achieved level; deferred and batch always throw."))
            : OptionState.Shown);
        SharedRules.TsaProviders(sandbox, Set);
        if (needsTsa)
        {
            SharedRules.CheckTsa(o.Timestamp, L.T("Signature TSA"), state, Error, sandbox, StepType);
            if (needsArchive && o.SeparateArchiveTsa)
            {
                SharedRules.CheckTsa(o.ArchiveTimestamp, L.T("Archive TSA"), state, Error, sandbox, StepType);
            }
        }

        if (icp && o.IcpPolicy == IcpPolicyKind.AdRa && sandbox)
        {
            Info(StepType, L.T("AD-RA in the sandbox embeds simulated policy artifacts (PA, LPA and LPA signature); in Real mode they are downloaded from the ITI and the LPA signature is checked."));
        }

        if (icp && sandbox)
        {
            Info(StepType, L.T("Sandbox certificates do not chain to a real ICP-Brasil root, so the policy version is not filtered by root (Real mode picks the newest version that accepts the signer's AC Raiz)."));
        }

        // ── 4. Cryptography ────────────────────────────────────────────
        var effective = o with { Padding = SharedRules.Crypto(o.Hash, o.Padding, credential, state, Error, StepCrypto) };

        Set("subFilter", icp ? new OptionState(true, L.T("ICP-Brasil PAdES policies mandate /Filter /PBAD_PAdES /SubFilter /PBAD.PAdES (DOC-ICP-15.03).")) : OptionState.Shown);
        Set("subFilter.EtsiCadesDetached", icp ? OptionState.Off(L.T("Fixed by the ICP-Brasil policy."))
            : pdfA1Preserved ? OptionState.Off(L.T("PDF/A-1 (ISO 19005-1) only allows adbe.pkcs7.detached signatures."))
            : OptionState.Shown);
        Set("subFilter.AdbePkcs7Detached", icp ? OptionState.Off(L.T("Fixed by the ICP-Brasil policy."))
            : o.Level != BaselineLevel.BB ? OptionState.Off(L.T("Legacy PKCS#7: only for B-B. B-T and above need ETSI.CAdES.detached."))
            : OptionState.Shown);
        Set("subFilter.PbadPades", OptionState.Off(L.T("Set automatically by the ICP-Brasil policies (choose ICP-Brasil in Signature type).")));
        effective = effective with
        {
            SubFilter = icp ? SubFilterChoice.PbadPades
                : pdfA1Preserved ? SubFilterChoice.AdbePkcs7Detached
                : o.SubFilter == SubFilterChoice.PbadPades ? SubFilterChoice.EtsiCadesDetached
                : o.SubFilter,
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
        Set("details.Metadata", OptionState.Shown);
        Set("details.Aea", icp ? OptionState.Off(L.T("AEA (Lei 14.063) is the non-ICP route: an ICP-Brasil signature is already a qualified signature (QES) and carries its own policy."))
            : kind == SignatureKind.CustomPolicy ? OptionState.Off(L.T("AEA writes its own signature-policy-identifier; it cannot be combined with a custom policy."))
            : OptionState.Shown);
        Set("metadata.policy", kind != SignatureKind.Baseline ? new OptionState(false, Note: L.T("The signature policy comes from the Signature type step.")) : OptionState.Shown);
        if (o.UseSignerDetails && builderOnly is null)
        {
            if (o.SignerDetails == SignerDetailsKind.Aea)
            {
                if (state["details.Aea"].Disabled is { } aeaReason)
                {
                    Error(StepDetails, aeaReason);
                }

                if (string.IsNullOrWhiteSpace(o.Aea.SignerName))
                {
                    Error(StepDetails, L.T("AEA: the signer name is required."));
                }

                if (!IsCpf(o.Aea.Cpf))
                {
                    Error(StepDetails, L.T("AEA: enter a valid CPF (11 digits with check digits)."));
                }
            }
            else if (string.IsNullOrWhiteSpace(o.Metadata.SignerName))
            {
                Error(StepDetails, L.T("Signer metadata: the signer name is required."));
            }
        }

        string? docInfoReason = builderOnly ?? (existing ? L.T("The document information dictionary cannot be changed when signing an existing field.") : null);
        Set("documentInfo", docInfoReason is not null ? OptionState.Off(docInfoReason) : OptionState.Shown);
        string? healthReason = builderOnly ?? (existing ? L.T("Health-document metadata is written to the document information dictionary, which cannot be changed when signing an existing field.") : null);
        Set("health", healthReason is not null ? OptionState.Off(healthReason) : OptionState.Shown);
        if (o.Health.Enabled && docInfoReason is null && o.Health.Professionals.Count == 0)
        {
            Error(StepDetails, L.T("Health document: add at least one professional registration."));
        }

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
        SharedRules.Signer(credential, Error, Warn, StepSigner);
        if (credential is not null)
        {
            if (icp && !sandbox && !credential.ChainsToIcpBrasil)
            {
                Warn(StepType, L.T("The certificate does not chain to an ICP-Brasil root: the signature will carry the policy, but it will not be valid under it."));
            }
        }

        return new OptionsReport(state, issues, effective, LevelName(effective));
    }

    /// <summary>The level as shown to users (B-B… or AD-RB…).</summary>
    public static string LevelName(SigningOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return options.Kind == SignatureKind.IcpBrasil
            ? options.IcpPolicy switch
            {
                IcpPolicyKind.AdRb => options.IcpAdRbTimestamp ? "AD-RB (B-T)" : "AD-RB (B-B)",
                IcpPolicyKind.AdRt => "AD-RT (B-T)",
                IcpPolicyKind.AdRc => "AD-RC (B-LTA)",
                _ => "AD-RA (B-LTA)",
            }
            : options.Level switch
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

    internal static bool IsCpf(string? value)
    {
        string digits = string.Concat((value ?? "").Where(char.IsAsciiDigit));
        if (digits.Length != 11 || digits.Distinct().Count() == 1)
        {
            return false;
        }

        int Check(int length)
        {
            int sum = 0;
            for (int i = 0; i < length; i++)
            {
                sum += (digits[i] - '0') * (length + 1 - i);
            }

            int rest = sum % 11;
            return rest < 2 ? 0 : 11 - rest;
        }

        return Check(9) == digits[9] - '0' && Check(10) == digits[10] - '0';
    }
}
