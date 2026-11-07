using SimpleSign.Brazil.Fiscal;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Localization;
using SimpleSign.TestBench.Sandbox;
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
}

/// <summary>
/// Which XML options combine: XAdES (<c>XadesSignerBuilder</c>, <c>WithIcpBrasilPolicy</c>) and the
/// fiscal XML-DSig profiles (<c>FiscalXmlSigner</c>). Each rule says why.
/// </summary>
public static class XmlCompatibility
{
    public const string StepData = "data";
    public const string StepSigner = "signer";
    public const string StepType = "type";
    public const string StepCrypto = "crypto";
    public const string StepDetails = "details";

    private static readonly HashSet<CredentialKind> LocalKeys = [CredentialKind.SandboxA1, CredentialKind.Pfx, CredentialKind.OsStore];

    public static XmlOptionsReport Evaluate(XmlOptions options, XmlFacts? data, CredentialFacts? credential)
    {
        ArgumentNullException.ThrowIfNull(options);
        var state = new Dictionary<string, OptionState>(StringComparer.Ordinal);
        var issues = new List<OptionIssue>();
        var o = options;
        bool sandbox = o.Environment == EnvironmentMode.Sandbox;
        bool fiscal = o.Mode == XmlMode.Fiscal;

        void Set(string key, OptionState value) => state[key] = value;
        void Error(string step, string message) => issues.Add(new(IssueSeverity.Error, step, message));
        void Warn(string step, string message) => issues.Add(new(IssueSeverity.Warning, step, message));
        void Info(string step, string message) => issues.Add(new(IssueSeverity.Info, step, message));

        Set("mode.Xades", OptionState.Shown);
        Set("mode.Fiscal", OptionState.Shown);

        // ── 1. Data ────────────────────────────────────────────────────
        if (data is null)
        {
            Error(StepData, L.T("Choose the XML to sign."));
        }
        else if (data.Error is not null)
        {
            Error(StepData, L.T("The file is not well-formed XML: {0}", data.Error));
        }

        var effective = o;
        string level;
        if (fiscal)
        {
            level = EvaluateFiscal(o, data, credential, state, Error, Warn, Info, out effective);
        }
        else
        {
            level = EvaluateXades(o, data, credential, state, Error, sandbox, out effective);
        }

        // ── 2. Signer ──────────────────────────────────────────────────
        if (!fiscal)
        {
            state["signingPolicy"] = OptionState.Shown;
        }

        SharedRules.Signer(credential, Error, Warn, StepSigner, fiscal ? null : o.SigningPolicy);
        if (fiscal && credential is not null && credential.KeyAlgorithm != "RSA")
        {
            Error(StepSigner, L.T("The fiscal layouts sign with RSA (rsa-sha1 / rsa-sha256): an {0} certificate cannot be used.", credential.KeyAlgorithm));
        }

        if (fiscal && credential is not null && credential.Cnpj is null)
        {
            Info(StepSigner, L.T("SEFAZ expects the emitter's e-CNPJ (the sandbox company certificate has one); this certificate has only a CPF."));
        }

        if (!fiscal && o.Kind == XadesKind.IcpBrasil && credential is not null && !sandbox && !credential.ChainsToIcpBrasil)
        {
            Warn(StepType, L.T("The certificate does not chain to an ICP-Brasil root: the signature will carry the policy, but it will not be valid under it."));
        }

        return new XmlOptionsReport(state, issues, effective, level);
    }

    private static string EvaluateXades(XmlOptions o, XmlFacts? data, CredentialFacts? credential, Dictionary<string, OptionState> state,
        Action<string, string> error, bool sandbox, out XmlOptions effective)
    {
        void Set(string key, OptionState value) => state[key] = value;
        Set("profile", OptionState.Hidden);
        Set("elementId", OptionState.Hidden);
        Set("signAll", OptionState.Hidden);

        // A countersignature signs the ds:SignatureValue of a signature the document already has.
        bool counterSign = o.CounterSign;
        Set("counterSign", OptionState.Shown);
        Set("counterSignatureId", counterSign ? OptionState.Shown : OptionState.Hidden);
        string insideSignature = L.T("A countersignature lives inside the signature it countersigns and signs no data of its own.");
        if (counterSign && data is { Error: null, Signatures: 0 })
        {
            error(StepData, L.T("The document has no signature to countersign."));
        }

        if (counterSign && o.Kind == XadesKind.IcpBrasil)
        {
            error(StepType, L.T("The TestBench builds countersignatures with the baseline levels or a custom policy, not with the ICP-Brasil policies."));
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

        bool icp = o.Kind == XadesKind.IcpBrasil;
        Set("icpPolicy", icp ? OptionState.Shown : OptionState.Hidden);
        Set("level", icp ? new OptionState(false, Note: L.T("The ICP-Brasil policy sets the level.")) : OptionState.Shown);
        Set("customPolicy", o.Kind == XadesKind.CustomPolicy ? OptionState.Shown : OptionState.Hidden);
        if (o.Kind == XadesKind.CustomPolicy && !Compatibility.IsOid(o.PolicyOid))
        {
            error(StepType, L.T("The policy OID must be dotted digits (e.g. 2.16.76.1.7.1.1.2.3)."));
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
        Set("extendedForm", icp ? new OptionState(false, Note: L.T("The ICP-Brasil policy sets the extended form (AD-RV: references, AD-RC: references and values, AD-RA: archive).")) : OptionState.Shown);
        string needsTimestamp = L.T("Extended forms need a signature timestamp: choose B-T or above.");
        string replacesLt = L.T("With an extended form the library builds XAdES-X / X-L / A instead of the B-LT / B-LTA data: choose B-T, the form adds the rest.");
        foreach (var form in Enum.GetValues<XadesExtendedChoice>())
        {
            Set($"extendedForm.{form}", form == XadesExtendedChoice.None ? OptionState.Shown
                : o.Level == BaselineLevel.BB ? OptionState.Off(needsTimestamp)
                : o.Level != BaselineLevel.BT ? OptionState.Off(replacesLt)
                : OptionState.Shown);
        }

        var extended = icp ? XadesExtendedChoice.None : o.ExtendedForm;
        if (!icp && state[$"extendedForm.{extended}"].Disabled is { } reason)
        {
            error(StepType, reason);
        }

        // The data objects timestamp is taken before signing, at any level.
        Set("dataObjectsTimestamp", counterSign ? OptionState.Off(insideSignature) : OptionState.Shown);
        bool dataObjectsTimestamp = o.DataObjectsTimestamp && !counterSign;
        bool needsTsa = dataObjectsTimestamp || (icp ? o.IcpPolicy != XadesIcpPolicy.AdRb : o.Level != BaselineLevel.BB);
        Set("timestamp", needsTsa ? OptionState.Shown : OptionState.Hidden);
        SharedRules.TsaProviders(sandbox, Set);
        if (needsTsa)
        {
            SharedRules.CheckTsa(o.Timestamp, L.T("Signature TSA"), state, error, sandbox, StepType);
        }

        var padding = SharedRules.Crypto(o.Hash, o.Padding, credential, state, error, StepCrypto);
        Set("hash", OptionState.Shown);

        Set("signingCertificate", icp ? new OptionState(true, L.T("The ICP-Brasil XML policies mandate the XAdES 1.3.2 SigningCertificate (V1).")) : OptionState.Shown);
        Set("roles", OptionState.Shown);
        bool legacyForm = icp || o.SigningCertificateV1;
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
        Set("revocationPreference", !icp && o.Level >= BaselineLevel.BLT ? OptionState.Shown : OptionState.Hidden);
        Set("commitment", OptionState.Shown);
        if (o.Commitment is { } commitment && !Enum.TryParse<Core.Signing.CommitmentType>(commitment, out _))
        {
            error(StepDetails, L.T("Unknown commitment type."));
        }

        effective = o with
        {
            Padding = padding,
            ExtendedForm = extended,
            SigningCertificateV1 = icp || o.SigningCertificateV1,
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
        return icp
            ? o.IcpPolicy switch
            {
                XadesIcpPolicy.AdRb => "AD-RB (B-B)",
                XadesIcpPolicy.AdRt => "AD-RT (B-T)",
                XadesIcpPolicy.AdRv => "AD-RV (XAdES-X)",
                XadesIcpPolicy.AdRc => "AD-RC (XAdES-X-L)",
                _ => "AD-RA (XAdES-A)",
            }
            : (o.Level switch { BaselineLevel.BB => "B-B", BaselineLevel.BT => "B-T", BaselineLevel.BLT => "B-LT", _ => "B-LTA" })
                + extended switch
                {
                    XadesExtendedChoice.CompleteReferences => " + XAdES-X",
                    XadesExtendedChoice.ExtendedLong => " + XAdES-X-L",
                    XadesExtendedChoice.Archive => " + XAdES-A",
                    _ => "",
                };
    }

    private static string EvaluateFiscal(XmlOptions o, XmlFacts? data, CredentialFacts? credential, Dictionary<string, OptionState> state,
        Action<string, string> error, Action<string, string> warn, Action<string, string> info, out XmlOptions effective)
    {
        void Set(string key, OptionState value) => state[key] = value;
        string fixedByLayout = L.T("Fixed by the fiscal layout: enveloped XML-DSig, C14N, only the signer certificate in KeyInfo, no XAdES properties.");
        foreach (string key in new[] { "form", "dataUri", "kind", "icpPolicy", "level", "customPolicy", "extendedForm", "timestamp", "padding", "signingCertificate", "roles", "mimeType", "productionPlace", "revocationPreference", "signingPolicy", "canonicalization", "counterSign", "counterSignatureId", "dataObjectsTimestamp", "certifiedRoles", "additionalObjects", "commitment" })
        {
            Set(key, new OptionState(false, Note: fixedByLayout));
        }

        foreach (string key in FiscalDocumentProfile.ByName.Keys)
        {
            Set($"profile.{key}", OptionState.Shown);
        }

        if (!FiscalDocumentProfile.ByName.TryGetValue(o.Profile, out var profile))
        {
            error(StepData, L.T("Unknown fiscal profile {0}.", o.Profile));
            effective = o;
            return "XML-DSig";
        }

        string hash = profile.HashAlgorithm.Name == "SHA1" ? "SHA-1" : "SHA-256";
        Set("hash", new OptionState(false, Note: L.T("The {0} layout fixes the digest: {1} (rsa-{2}).", profile.Name, hash, hash.Replace("-", "", StringComparison.Ordinal).ToLowerInvariant())));
        if (hash == "SHA-1" && credential is not null && !LocalKeys.Contains(credential.Kind))
        {
            warn(StepSigner, L.T("This layout signs with RSA-SHA1: {0} signers may refuse SHA-1 digests.", credential.Kind));
        }

        bool local = credential is null || LocalKeys.Contains(credential.Kind);
        IReadOnlyList<string> targets = data?.FiscalTargets.TryGetValue(o.Profile, out var t) == true ? t : [];
        bool wholeDocument = profile.SignedElement is null;
        Set("signAll", wholeDocument ? new OptionState(false, Note: L.T("This layout signs the whole document (URI=\"\"): there is one signature."))
            : !local ? OptionState.Off(L.T("FiscalXmlSigner.SignAll needs a local key; with a token or cloud signer, sign one element at a time (SignAsync)."))
            : OptionState.Shown);
        bool signAll = o.SignAll && state["signAll"].Visible && state["signAll"].Disabled is null;
        if (o.SignAll && !wholeDocument && !local)
        {
            error(StepData, state["signAll"].Disabled!);
        }

        Set("elementId", !wholeDocument && !signAll && targets.Count > 1 ? OptionState.Shown : OptionState.Hidden);
        if (data is { Error: null })
        {
            if (targets.Count == 0)
            {
                error(StepData, profile.IdAttribute == "id" && profile.SignedElement == "*"
                    ? L.T("No event with an id attribute under the root: this is not an {0} document.", profile.Name)
                    : L.T("No <{0} {1}=\"…\"> element: this is not a {2} document.", profile.SignedElement!, profile.IdAttribute!, profile.Name));
            }
            else if (!wholeDocument && !signAll && targets.Count > 1 && string.IsNullOrWhiteSpace(o.ElementId))
            {
                error(StepData, L.T("The document has {0} <{1}> elements: choose the Id to sign, or sign all.", targets.Count, profile.SignedElement!));
            }
            else if (!string.IsNullOrWhiteSpace(o.ElementId) && !signAll && !targets.Contains(o.ElementId))
            {
                error(StepData, L.T("No <{0}> with Id {1}.", profile.SignedElement!, o.ElementId));
            }

            if (data.Signatures > 0 && !signAll)
            {
                info(StepData, L.T("The document already has {0} signature(s); FiscalXmlSigner adds one more.", data.Signatures));
            }
        }

        effective = o with { SignAll = signAll, ElementId = signAll || targets.Count <= 1 ? null : o.ElementId };
        return $"XML-DSig {profile.Name} ({hash})";
    }
}
