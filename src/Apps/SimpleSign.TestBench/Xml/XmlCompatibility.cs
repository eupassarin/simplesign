using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Localization;
using SimpleSign.TestBench.Signing;

namespace SimpleSign.TestBench.Xml;

/// <summary>The result of the XML rules.</summary>
public sealed record XmlOptionsReport(
    IReadOnlyDictionary<string, OptionState> Options,
    IReadOnlyList<OptionIssue> Issues,
    XmlOptions Effective,
    string EffectiveLevel)
{
    public bool CanSign => Issues.All(i => i.Severity != IssueSeverity.Error);

    /// <summary>Whether the run may go on (see <see cref="OptionsReport.CanRun"/>).</summary>
    public bool CanRun => !OptionIssue.Block(Issues, Effective.AttemptRefused);
}

/// <summary>
/// Which XAdES options combine (<c>XadesSignerBuilder</c>). Each rule says why.
/// </summary>
public static class XmlCompatibility
{
    public const string StepData = "data";
    public const string StepSigner = "signer";
    public const string StepType = "type";
    public const string StepCrypto = "crypto";
    public const string StepDetails = "details";

    public static XmlOptionsReport Evaluate(XmlOptions options, XmlFacts? data, CredentialFacts? credential, bool sandboxConnected = true, SigningPolicyInput? signingPolicy = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        var state = new Dictionary<string, OptionState>(StringComparer.Ordinal);
        var issues = new List<OptionIssue>();
        var o = options;

        void Set(string key, OptionState value) => state[key] = value;
        void Error(string step, string message) => issues.Add(new(IssueSeverity.Error, step, message));
        void Warn(string step, string message) => issues.Add(new(IssueSeverity.Warning, step, message));

        // ── 1. Data ────────────────────────────────────────────────────
        if (data is null)
        {
            Error(StepData, L.T("Choose the XML to sign."));
        }
        else if (data.Error is not null)
        {
            Error(StepData, L.T("The file is not well-formed XML: {0}", data.Error));
        }

        string level = EvaluateXades(o, data, credential, state, Error, sandboxConnected, out var effective);

        // ── 2. Signer ──────────────────────────────────────────────────
        Set("signingPolicy", OptionState.Shown);
        SharedRules.Signer(credential, Error, Warn, StepSigner, signingPolicy);
        return new XmlOptionsReport(state, issues, effective, level);
    }

    private static string EvaluateXades(XmlOptions o, XmlFacts? data, CredentialFacts? credential, Dictionary<string, OptionState> state,
        Action<string, string> error, bool sandboxConnected, out XmlOptions effective)
    {
        void Set(string key, OptionState value) => state[key] = value;

        // A countersignature signs the ds:SignatureValue of a signature the document already has.
        bool counterSign = o.CounterSign;
        Set("counterSign", OptionState.Shown);
        Set("counterSignatureId", counterSign ? OptionState.Shown : OptionState.Hidden);
        string insideSignature = L.T("A countersignature lives inside the signature it countersigns and signs no data of its own.");
        if (counterSign && data is { Error: null, Signatures: 0 })
        {
            error(StepData, L.T("The document has no signature to countersign."));
        }

        if (counterSign && (o.Level > BaselineLevel.BT || o.ExtendedForm != XadesExtendedChoice.None))
        {
            error(StepType, L.T("A countersignature is built at B-B or B-T, without an extended form."));
        }

        foreach (var form in Enum.GetValues<XadesFormChoice>())
        {
            Set($"form.{form}", counterSign ? OptionState.Off(insideSignature) : OptionState.Shown);
        }

        Set("dataUri", o.Form == XadesFormChoice.Detached && !counterSign ? OptionState.Shown : OptionState.Hidden);
        if (counterSign)
        {
            // Nothing to check: the form does not apply.
        }
        else if (o.Form == XadesFormChoice.Detached && !Uri.TryCreate(o.DataUri, UriKind.RelativeOrAbsolute, out _) || o.Form == XadesFormChoice.Detached && string.IsNullOrWhiteSpace(o.DataUri))
        {
            error(StepData, L.T("A detached signature needs the data URI its Reference points to (e.g. document.xml)."));
        }

        foreach (var kind in Enum.GetValues<XadesKind>())
        {
            Set($"kind.{kind}", OptionState.Shown);
        }

        Set("level", OptionState.Shown);
        Set("customPolicy", o.Kind == XadesKind.CustomPolicy ? OptionState.Shown : OptionState.Hidden);
        if (o.Kind == XadesKind.CustomPolicy && !Compatibility.IsOid(o.PolicyOid))
        {
            error(StepType, L.T("The policy OID must be dotted digits (e.g. 1.2.3.4.5)."));
        }

        if (o.Kind == XadesKind.CustomPolicy && !string.IsNullOrWhiteSpace(o.PolicyUri) && !Uri.TryCreate(o.PolicyUri, UriKind.Absolute, out _))
        {
            error(StepType, L.T("The policy URI must be an absolute URL."));
        }

        if (o.Kind == XadesKind.CustomPolicy && !string.IsNullOrEmpty(o.PolicyDocumentId)
            && (string.IsNullOrWhiteSpace(o.PolicySpecification) || !o.PolicySpecification.All(char.IsAscii)))
        {
            error(StepType, L.T("The policy document specification must be an OID or a URI (ASCII only)."));
        }

        foreach (var l in Enum.GetValues<BaselineLevel>())
        {
            Set($"level.{l}", OptionState.Shown);
        }

        // XadesSignerBuilder builds the extended form instead of the B-LT / B-LTA material: on
        // B-LT or B-LTA the achieved level would not be the one asked for.
        Set("extendedForm", OptionState.Shown);
        string needsTimestamp = L.T("Extended forms need a signature timestamp: choose B-T or above.");
        string replacesLt = L.T("With an extended form the library builds XAdES-X / X-L / A instead of the B-LT / B-LTA data: choose B-T, the form adds the rest.");
        foreach (var form in Enum.GetValues<XadesExtendedChoice>())
        {
            Set($"extendedForm.{form}", form == XadesExtendedChoice.None ? OptionState.Shown
                : o.Level == BaselineLevel.BB ? OptionState.Off(needsTimestamp)
                : o.Level != BaselineLevel.BT ? OptionState.Off(replacesLt)
                : OptionState.Shown);
        }

        var extended = o.ExtendedForm;
        if (state[$"extendedForm.{extended}"].Disabled is { } reason)
        {
            error(StepType, reason);
        }

        // The data objects timestamp is taken before signing, at any level.
        Set("dataObjectsTimestamp", counterSign ? OptionState.Off(insideSignature) : OptionState.Shown);
        bool dataObjectsTimestamp = o.DataObjectsTimestamp && !counterSign;
        bool needsTsa = dataObjectsTimestamp || o.Level != BaselineLevel.BB;
        Set("timestamp", needsTsa ? OptionState.Shown : OptionState.Hidden);
        SharedRules.TsaProviders(sandboxConnected, Set);
        if (needsTsa)
        {
            SharedRules.CheckTsa(o.Timestamp, L.T("Signature TSA"), state, error, StepType);
        }

        var padding = SharedRules.Crypto(o.Hash, o.Padding, credential, state, error, StepCrypto);
        Set("hash", OptionState.Shown);

        Set("signingCertificate", OptionState.Shown);
        Set("roles", OptionState.Shown);
        bool legacyForm = o.SigningCertificateV1;
        Set("certifiedRoles", legacyForm
            ? OptionState.Off(L.T("Attribute certificates and signed assertions go in SignerRoleV2, which the XAdES 1.3.2 form does not have."))
            : OptionState.Shown);
        Set("additionalObjects", counterSign ? OptionState.Off(insideSignature) : OptionState.Shown);
        Set("mimeType", counterSign ? OptionState.Off(insideSignature) : OptionState.Shown);
        Set("productionPlace", OptionState.Shown);
        if (legacyForm && !string.IsNullOrWhiteSpace(o.PlaceStreet))
        {
            error(StepDetails, L.T("The street address goes in SignatureProductionPlaceV2, which the XAdES 1.3.2 form does not have: leave it empty."));
        }

        Set("canonicalization", OptionState.Shown);
        Set("revocationPreference", o.Level >= BaselineLevel.BLT ? OptionState.Shown : OptionState.Hidden);
        Set("commitment", OptionState.Shown);
        if (o.Commitment is { } commitment && !Enum.TryParse<Core.Signing.CommitmentType>(commitment, out _))
        {
            error(StepDetails, L.T("Unknown commitment type."));
        }

        effective = o with
        {
            Padding = padding,
            ExtendedForm = extended,
            SignerRoles = [.. o.SignerRoles.Where(r => !string.IsNullOrWhiteSpace(r)).Select(r => r.Trim())],
            Form = counterSign ? XadesFormChoice.Enveloped : o.Form,
            AttributeCertificateId = legacyForm ? null : SigningPlan.Blank(o.AttributeCertificateId),
            SignedAssertionId = legacyForm ? null : SigningPlan.Blank(o.SignedAssertionId),
            EmbeddedObjectId = counterSign ? null : SigningPlan.Blank(o.EmbeddedObjectId),
            ExternalObjectId = counterSign ? null : SigningPlan.Blank(o.ExternalObjectId),
            MimeType = counterSign ? null : o.MimeType,
            DataObjectsTimestamp = dataObjectsTimestamp,
            CounterSignatureId = counterSign ? SigningPlan.Blank(o.CounterSignatureId)?.Trim() : null,
            PlaceCity = SigningPlan.Blank(o.PlaceCity),
            PlaceStreet = SigningPlan.Blank(o.PlaceStreet),
            PlaceState = SigningPlan.Blank(o.PlaceState),
            PlacePostalCode = SigningPlan.Blank(o.PlacePostalCode),
            PlaceCountry = SigningPlan.Blank(o.PlaceCountry),
        };
        return (o.Level switch { BaselineLevel.BB => "B-B", BaselineLevel.BT => "B-T", BaselineLevel.BLT => "B-LT", _ => "B-LTA" })
            + extended switch
            {
                XadesExtendedChoice.CompleteReferences => " + XAdES-X",
                XadesExtendedChoice.ExtendedLong => " + XAdES-X-L",
                XadesExtendedChoice.Archive => " + XAdES-A",
                _ => "",
            };
    }
}
