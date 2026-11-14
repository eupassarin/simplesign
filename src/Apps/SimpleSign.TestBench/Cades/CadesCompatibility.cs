using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Localization;
using SimpleSign.TestBench.Signing;

namespace SimpleSign.TestBench.Cades;

/// <summary>What the CAdES rules need to know about the data and the existing signature.</summary>
/// <param name="DataName">The data file's name (null: no data chosen).</param>
/// <param name="Existing">The signature to co-sign or countersign (null: none chosen).</param>
/// <param name="DataMatchesExisting">For a detached existing signature: whether the data is the signed content.</param>
public sealed record CadesInputs(string? DataName, CmsFacts? Existing, bool? DataMatchesExisting);

/// <summary>The result of the CAdES rules, like <see cref="OptionsReport"/> for PDF.</summary>
public sealed record CadesOptionsReport(
    IReadOnlyDictionary<string, OptionState> Options,
    IReadOnlyList<OptionIssue> Issues,
    CadesOptions Effective,
    string EffectiveLevel)
{
    public bool CanSign => Issues.All(i => i.Severity != IssueSeverity.Error);

    /// <summary>Whether the run may go on (see <see cref="OptionsReport.CanRun"/>).</summary>
    public bool CanRun => !OptionIssue.Block(Issues, Effective.AttemptRefused);
}

/// <summary>
/// Which CAdES options combine. Every rule mirrors a library constraint (<c>CadesSigner</c>,
/// <c>CadesSignerBuilder</c>) and says why.
/// </summary>
public static class CadesCompatibility
{
    public const string StepData = "data";
    public const string StepSigner = "signer";
    public const string StepType = "type";
    public const string StepCrypto = "crypto";
    public const string StepDetails = "details";

    public static CadesOptionsReport Evaluate(CadesOptions options, CadesInputs inputs, CredentialFacts? credential, bool sandboxConnected = true, SigningPolicyInput? signingPolicy = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(inputs);
        var state = new Dictionary<string, OptionState>(StringComparer.Ordinal);
        var issues = new List<OptionIssue>();
        // An ICP-Brasil policy sets the level and the extended form (DOC-ICP-15.03): a timestamp from AD-RT up.
        var o = options.Kind == CadesKind.IcpBrasil
            ? options with { Level = options.IcpPolicy == SimpleSign.Brazil.IcpBrasil.IcpBrasilPolicy.AdRb ? BaselineLevel.BB : BaselineLevel.BT, ExtendedForm = CadesExtendedChoice.None }
            : options;

        void Set(string key, OptionState value) => state[key] = value;
        void Error(string step, string message) => issues.Add(new(IssueSeverity.Error, step, message));
        void Warn(string step, string message) => issues.Add(new(IssueSeverity.Warning, step, message));
        void Info(string step, string message) => issues.Add(new(IssueSeverity.Info, step, message));

        // ── 1. Data and operation ──────────────────────────────────────
        foreach (var operation in Enum.GetValues<CadesOperation>())
        {
            Set($"operation.{operation}", OptionState.Shown);
        }

        var existing = inputs.Existing;
        bool coSign = o.Operation == CadesOperation.CoSign;
        bool counterSign = o.Operation == CadesOperation.CounterSign;
        bool needsExisting = coSign || counterSign;
        Set("existing", needsExisting ? OptionState.Shown : OptionState.Hidden);
        var contentType = o.ContentType;
        if (needsExisting)
        {
            if (existing is null)
            {
                Error(StepData, coSign ? L.T("Choose the signature to co-sign.") : L.T("Choose the signature to countersign."));
            }
            else if (existing.Error is not null)
            {
                Error(StepData, L.T("The file is not a CMS SignedData: {0}", existing.Error));
            }
        }

        bool existingOk = existing is { Error: null };
        bool existingDetached = existingOk && existing!.IsDetached;
        bool dataNeeded = o.Operation == CadesOperation.Sign || coSign && (existing is null || existingDetached);
        Set("data", dataNeeded ? OptionState.Shown
            : counterSign && existingDetached ? new OptionState(true, Note: L.T("Optional: the content of the detached signature, used only to validate the result. A countersignature signs the other signer's signature value, not the content."))
            : counterSign ? new OptionState(false, Note: L.T("A countersignature signs the other signer's signature value, not the content."))
            : new OptionState(false, Note: L.T("The content is inside the .p7m: CoSign takes it from there.")));
        if (dataNeeded && inputs.DataName is null)
        {
            Error(StepData, coSign ? L.T("The signature is detached: choose the data it signed.") : L.T("Choose the data to sign."));
        }

        if (coSign && existingDetached && inputs.DataMatchesExisting == false)
        {
            Error(StepData, L.T("This data is not the content signed by the existing signature (message digest differs): CoSign refuses it."));
        }

        if (counterSign && existingDetached && inputs.DataMatchesExisting == false)
        {
            Error(StepData, L.T("This data is not the content signed by the existing signature (message digest differs): the result could not be validated against it. Choose the right data or none."));
        }

        Set("contentType", o.Operation == CadesOperation.Sign ? OptionState.Shown
            : coSign ? new OptionState(true, L.T("A co-signature keeps the existing content type."))
            : new OptionState(false, Note: L.T("A countersignature lives inside the signer it countersigns: the file keeps the existing content type.")));
        foreach (var choice in Enum.GetValues<CadesContentChoice>())
        {
            Set($"contentType.{choice}", o.Operation == CadesOperation.Sign ? OptionState.Shown : OptionState.Off(L.T("Fixed by the existing signature.")));
        }

        if (needsExisting && existingOk)
        {
            contentType = existingDetached ? CadesContentChoice.Detached : CadesContentChoice.Enveloped;
        }

        Set("signerIndex", counterSign ? OptionState.Shown : OptionState.Hidden);
        if (counterSign && existingOk && (o.SignerIndex < 0 || o.SignerIndex >= existing!.Signers.Count))
        {
            Error(StepData, L.T("Signer {0} does not exist: the signature has {1} signer(s).", o.SignerIndex + 1, existing!.Signers.Count));
        }

        // ── 3. Signature type ──────────────────────────────────────────
        foreach (var kind in Enum.GetValues<CadesKind>())
        {
            Set($"kind.{kind}", OptionState.Shown);
        }

        Set("level", OptionState.Shown);
        Set("icpPolicy", o.Kind == CadesKind.IcpBrasil ? OptionState.Shown : OptionState.Hidden);
        Set("customPolicy", o.Kind == CadesKind.CustomPolicy ? OptionState.Shown : OptionState.Hidden);
        if (o.Kind == CadesKind.CustomPolicy && !Compatibility.IsOid(o.PolicyOid))
        {
            Error(StepType, L.T("The policy OID must be dotted digits (e.g. 1.2.3.4.5)."));
        }

        if (o.Kind == CadesKind.CustomPolicy && !string.IsNullOrWhiteSpace(o.PolicyUri) && !Uri.TryCreate(o.PolicyUri, UriKind.Absolute, out _))
        {
            Error(StepType, L.T("The policy URI must be an absolute URL."));
        }

        if (o.Kind == CadesKind.CustomPolicy && !string.IsNullOrEmpty(o.PolicyDocumentId)
            && (string.IsNullOrWhiteSpace(o.PolicySpecification) || !o.PolicySpecification.All(char.IsAscii)))
        {
            Error(StepType, L.T("The policy document specification must be an OID or a URI (ASCII only)."));
        }

        foreach (var level in Enum.GetValues<BaselineLevel>())
        {
            Set($"level.{level}", OptionState.Shown);
        }

        // Extended forms build on the signature timestamp (B-T, B-LT or B-LTA).
        Set("extendedForm", OptionState.Shown);
        string needsTimestamp = L.T("Extended forms need a signature timestamp: choose B-T or above.");
        foreach (var form in Enum.GetValues<CadesExtendedChoice>())
        {
            Set($"extendedForm.{form}", form == CadesExtendedChoice.None || o.Level != BaselineLevel.BB ? OptionState.Shown : OptionState.Off(needsTimestamp));
        }

        var extended = o.ExtendedForm;
        if (state[$"extendedForm.{extended}"].Disabled is { } extendedReason)
        {
            Error(StepType, extendedReason);
        }

        // The content timestamp is taken before signing, at any level, and a countersignature has no content.
        Set("contentTimestamp", counterSign
            ? OptionState.Off(L.T("A countersignature signs a signature value, not content: it cannot carry a content timestamp."))
            : OptionState.Shown);
        bool contentTimestamp = o.ContentTimestamp && !counterSign;
        bool needsTsa = contentTimestamp || o.Level != BaselineLevel.BB;
        Set("timestamp", needsTsa ? OptionState.Shown : OptionState.Hidden);
        SharedRules.TsaProviders(sandboxConnected, Set);
        if (needsTsa)
        {
            SharedRules.CheckTsa(o.Timestamp, L.T("Signature TSA"), state, Error, StepType);
        }

        if (counterSign && (o.Level >= BaselineLevel.BLT || extended != CadesExtendedChoice.None))
        {
            Info(StepType, L.T("The countersignature gets its own validation data; the parent signer is left as it was."));
        }

        // ── 4. Cryptography ────────────────────────────────────────────
        var padding = SharedRules.Crypto(o.Hash, o.Padding, credential, state, Error, StepCrypto);

        // ── 5. Details ─────────────────────────────────────────────────
        Set("commitment", OptionState.Shown);
        if (o.Commitment is { } commitment && !Enum.TryParse<Core.Signing.CommitmentType>(commitment, out _))
        {
            Error(StepDetails, L.T("Unknown commitment type."));
        }

        Set("revocationPreference", o.Level >= BaselineLevel.BLT ? OptionState.Shown : OptionState.Hidden);
        Set("signerLocation", OptionState.Shown);
        Set("roles", OptionState.Shown);
        Set("certifiedRoles", OptionState.Shown);
        var postalAddress = Lines(o.SignerPostalAddress);
        if (postalAddress.Count > 6)
        {
            Error(StepDetails, L.T("The postal address of the signer location takes at most six lines."));
        }

        // content-hints and mime-type describe the signed content, which a countersignature does not sign.
        var describesContent = counterSign
            ? OptionState.Off(L.T("A countersignature cannot carry content-hints or mime-type (ETSI EN 319 122-1 §5.2.4)."))
            : OptionState.Shown;
        Set("mimeType", describesContent);
        Set("contentHints", describesContent);

        // ── 2. Signer ──────────────────────────────────────────────────
        Set("signingPolicy", OptionState.Shown);
        SharedRules.Signer(credential, Error, Warn, StepSigner, signingPolicy);
        var effective = o with
        {
            Padding = padding,
            ContentType = contentType,
            ExtendedForm = extended,
            ContentTimestamp = contentTimestamp,
            SignerCountry = SigningPlan.Blank(o.SignerCountry),
            SignerLocality = SigningPlan.Blank(o.SignerLocality),
            SignerPostalAddress = postalAddress,
            SignerRoles = Lines(o.SignerRoles),
            MimeType = counterSign ? null : SigningPlan.Blank(o.MimeType),
            ContentDescription = counterSign ? null : SigningPlan.Blank(o.ContentDescription),
        };
        return new CadesOptionsReport(state, issues, effective, LevelName(effective));
    }

    private static List<string> Lines(IReadOnlyList<string> lines) =>
        [.. lines.Where(l => !string.IsNullOrWhiteSpace(l)).Select(l => l.Trim())];

    /// <summary>The level as shown to users.</summary>
    public static string LevelName(CadesOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        string level = options.Level switch
        {
            BaselineLevel.BB => "B-B",
            BaselineLevel.BT => "B-T",
            BaselineLevel.BLT => "B-LT",
            _ => "B-LTA",
        };
        return options.ExtendedForm switch
        {
            CadesExtendedChoice.CompleteReferences => level + " + CAdES-X",
            CadesExtendedChoice.ExtendedLong => level + " + CAdES-X Long",
            CadesExtendedChoice.Archive => level + " + CAdES-A",
            _ => level,
        };
    }
}
