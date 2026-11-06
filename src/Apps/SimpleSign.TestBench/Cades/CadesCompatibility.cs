using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Localization;
using SimpleSign.TestBench.Sandbox;
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
}

/// <summary>
/// Which CAdES options combine. Every rule mirrors a library constraint (<c>CadesSigner</c>,
/// <c>CadesSignerBuilder</c>, <c>IcpBrasilCadesExtensions</c>) and says why.
/// </summary>
public static class CadesCompatibility
{
    public const string StepData = "data";
    public const string StepSigner = "signer";
    public const string StepType = "type";
    public const string StepCrypto = "crypto";
    public const string StepDetails = "details";

    public static CadesOptionsReport Evaluate(CadesOptions options, CadesInputs inputs, CredentialFacts? credential)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(inputs);
        var state = new Dictionary<string, OptionState>(StringComparer.Ordinal);
        var issues = new List<OptionIssue>();
        var o = options;
        bool sandbox = o.Environment == EnvironmentMode.Sandbox;

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

        bool icp = o.Kind == CadesKind.IcpBrasil;
        Set("icpPolicy", icp ? OptionState.Shown : OptionState.Hidden);
        Set("level", icp ? new OptionState(false, Note: L.T("The ICP-Brasil policy sets the level.")) : OptionState.Shown);
        Set("customPolicy", o.Kind == CadesKind.CustomPolicy ? OptionState.Shown : OptionState.Hidden);
        if (o.Kind == CadesKind.CustomPolicy && !Compatibility.IsOid(o.PolicyOid))
        {
            Error(StepType, L.T("The policy OID must be dotted digits (e.g. 2.16.76.1.7.1.1.2.3)."));
        }

        if (o.Kind == CadesKind.CustomPolicy && !string.IsNullOrWhiteSpace(o.PolicyUri) && !Uri.TryCreate(o.PolicyUri, UriKind.Absolute, out _))
        {
            Error(StepType, L.T("The policy URI must be an absolute URL."));
        }

        foreach (var level in Enum.GetValues<BaselineLevel>())
        {
            Set($"level.{level}", OptionState.Shown);
        }

        // Extended forms build on the signature timestamp (B-T, B-LT or B-LTA).
        Set("extendedForm", icp ? new OptionState(false, Note: L.T("The ICP-Brasil policy sets the extended form (AD-RV: references, AD-RC: references and values, AD-RA: archive)."))
            : OptionState.Shown);
        string needsTimestamp = L.T("Extended forms need a signature timestamp: choose B-T or above.");
        foreach (var form in Enum.GetValues<CadesExtendedChoice>())
        {
            Set($"extendedForm.{form}", form == CadesExtendedChoice.None || o.Level != BaselineLevel.BB ? OptionState.Shown : OptionState.Off(needsTimestamp));
        }

        var extended = icp ? CadesExtendedChoice.None : o.ExtendedForm;
        if (!icp && state[$"extendedForm.{extended}"].Disabled is { } extendedReason)
        {
            Error(StepType, extendedReason);
        }

        bool needsTsa = icp ? o.IcpPolicy != CadesIcpPolicy.AdRb : o.Level != BaselineLevel.BB;
        Set("timestamp", needsTsa ? OptionState.Shown : OptionState.Hidden);
        SharedRules.TsaProviders(sandbox, Set);
        if (needsTsa)
        {
            SharedRules.CheckTsa(o.Timestamp, L.T("Signature TSA"), state, Error, sandbox, StepType);
        }

        if (icp && sandbox)
        {
            Info(StepType, L.T("Sandbox certificates do not chain to a real ICP-Brasil root, so the policy version is not filtered by root (Real mode picks the newest version that accepts the signer's AC Raiz)."));
        }

        if (counterSign && (icp ? o.IcpPolicy >= CadesIcpPolicy.AdRv : o.Level >= BaselineLevel.BLT || extended != CadesExtendedChoice.None))
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

        // ── 2. Signer ──────────────────────────────────────────────────
        SharedRules.Signer(credential, Error, Warn, StepSigner);
        if (credential is not null && icp && !sandbox && !credential.ChainsToIcpBrasil)
        {
            Warn(StepType, L.T("The certificate does not chain to an ICP-Brasil root: the signature will carry the policy, but it will not be valid under it."));
        }

        var effective = o with { Padding = padding, ContentType = contentType, ExtendedForm = extended };
        return new CadesOptionsReport(state, issues, effective, LevelName(effective));
    }

    /// <summary>The level as shown to users.</summary>
    public static string LevelName(CadesOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.Kind == CadesKind.IcpBrasil)
        {
            return options.IcpPolicy switch
            {
                CadesIcpPolicy.AdRb => "AD-RB (B-B)",
                CadesIcpPolicy.AdRt => "AD-RT (B-T)",
                CadesIcpPolicy.AdRv => "AD-RV (CAdES-X)",
                CadesIcpPolicy.AdRc => "AD-RC (CAdES-X Long)",
                _ => "AD-RA (CAdES-A)",
            };
        }

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
