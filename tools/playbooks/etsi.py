"""Writes docs/playbooks/etsi-baseline.json: the steps of docs/playbooks/etsi-checklist.md a run can show, against the
TestBench's Sandbox.

Every step is tagged with the checklist items it covers (PA-n PAdES, CA-n CAdES, XA-n XAdES, AL-n all formats, EX-n
extended forms, TS-n time-stamps, VA-n validation, TL-n trusted lists, CE-n certificates) and the ETSI standard.
Items marked N or X in the checklist are not here.

    python3 tools/playbooks/etsi.py docs/playbooks/etsi-baseline.json
"""
import json
import sys

PADES, CADES, XADES = "EN 319 142-1", "EN 319 122-1", "EN 319 132-1"
VAL, TSP, TLS, CRYPTO = "EN 319 102-1", "RFC 3161", "TS 119 612", "TS 119 312"
STD = {"pades": PADES, "cades": CADES, "xades": XADES}
FMT = {"pades": {}, "cades": {"dataId": "cades-sample:text"}, "xades": {"dataId": "xades-sample:order"}}
TSA = {"provider": "Sandbox"}
LEVEL = {"BB": "B-B", "BT": "B-T", "BLT": "B-LT", "BLTA": "B-LTA"}


def sign(id, title, tags, expect, fmt="pades", desc=None, sandbox=None, **opts):
    s = {"id": id, "title": title, "tags": tags, "format": fmt, "options": {**FMT[fmt], **opts}, "expect": expect}
    if desc:
        s["description"] = desc
    if sandbox:
        s["sandbox"] = sandbox
    return s


def validate(id, title, tags, file_id, expect, desc=None, sandbox=None, data_id=None, wait=None, **settings):
    options = {"fileId": file_id}
    if data_id:
        options["dataId"] = data_id
    options["settings"] = {"trust": ["Sandbox"], **settings}
    s = {"id": id, "kind": "validate", "title": title, "tags": tags, "options": options, "expect": expect}
    if wait:
        s["wait"] = wait
    if desc:
        s["description"] = desc
    if sandbox:
        s["sandbox"] = sandbox
    return s


def augment(id, title, tags, file_id, level, desc=None, data_id=None, renew=False):
    options = {"fileId": file_id, "level": level, "timestamp": TSA}
    if data_id:
        options["dataId"] = data_id
    if renew:
        options["renew"] = True
    s = {"id": id, "kind": "augment", "title": title, "tags": tags, "options": options,
         "expect": {"outcome": "augmented", "level": LEVEL[level], "indication": "TOTAL_PASSED"}}
    if desc:
        s["description"] = desc
    return s


def chain(fmt, std, data_id=None):
    """B-B (the format's signing step) raised to B-T, then B-LT, then B-LTA, each validated."""
    steps, previous = [], f"step:{fmt}-bb"
    for lv in ("BT", "BLT", "BLTA"):
        steps.append(augment(f"aug-{fmt}-{lv.lower()}", f"{fmt.upper()}: augment to {LEVEL[lv]}", ["EX-3", std, "augment"], previous, lv,
                             data_id=data_id))
        previous = f"step:aug-{fmt}-{lv.lower()}"
    return steps


def signed(level=None, **more):
    return {"outcome": "signed", **({"level": LEVEL[level]} if level else {}), **more}


def refused(reason=None):
    return {"outcome": "refused", **({"reason": reason} if reason else {})}


def levels(fmt, items, **opts):
    """B-B, B-T, B-LT and B-LTA of one format, each validated (TOTAL_PASSED) after signing."""
    return [sign(f"{fmt}-{lv.lower()}", f"{fmt.upper()} {LEVEL[lv]}", [item, STD[fmt], "levels"], signed(lv, indication="TOTAL_PASSED"), fmt=fmt,
                 level=lv, **({"timestamp": TSA} if lv != "BB" else {}), **opts)
            for lv, item in zip(("BB", "BT", "BLT", "BLTA"), items)]


sections = [
    {"id": "pades", "title": "PAdES baseline (EN 319 142-1)",
     "description": "The four levels, then what a PDF signature adds: certification, incremental updates, PDF/A, the SubFilter, and the optional attributes.",
     "steps": [
         *levels("pades", ("PA-1", "PA-3", "PA-4", "PA-5")),
         sign("pades-blta-archive-tsa", "PAdES B-LTA with a separate archive TSA", ["PA-5", "TS-5", PADES, "tsa"], signed("BLTA"), level="BLTA",
              timestamp=TSA, separateArchiveTsa=True, archiveTimestamp=TSA),
         validate("pades-appended", "Content appended after the signature", ["PA-7", PADES, "integrity"], "sample:appended", {"outcome": "valid"},
                  desc="An incremental update after the signature: the signed revision is intact; the report says what came after."),
         *[sign(f"pades-certified-{p}", f"Certification (DocMDP P={p})", ["PA-8", PADES, "docmdp"], signed("BB"), certification=c)
           for p, c in ((1, "NoChanges"), (2, "FormFilling"), (3, "FormFillingAndAnnotations"))],
         sign("pades-attributes", "Reason and location", ["PA-9", PADES, "attributes"], signed("BB"),
              reason="Approval of the contract", location="Lima, PE"),
         sign("pades-policy", "Explicit signature policy (signature-policy-identifier)", ["PA-9", PADES, "policy"], {"outcome": "signed"},
              kind="CustomPolicy", customPolicy={"oid": "1.3.6.1.4.1.99999.1.1", "hashAlgorithm": "Sha256", "hashHex": "00" * 32,
                                                  "uri": "https://example.org/policy.der"}),
         sign("pades-pdfa", "Preserve PDF/A", ["PA-10", PADES, "pdfa"], {"outcome": "signed"}, preservePdfA=True),
         sign("pades-adbe", "adbe.pkcs7.detached SubFilter", ["PA-11", PADES, "subfilter"], {"outcome": "signed"}, subFilter="AdbePkcs7Detached",
              desc="The pre-PAdES SubFilter: still produced and read, but not a PAdES baseline signature."),
     ]},
    {"id": "cades", "title": "CAdES baseline (EN 319 122-1)",
     "description": "Detached and attached content, the optional signed attributes, co-signatures and countersignatures, and the four levels.",
     "steps": [
         *levels("cades", ("CA-1", "CA-5", "CA-6", "CA-7")),
         sign("cades-attached", "CAdES B-B, attached content (p7m)", ["CA-1", CADES], signed("BB", indication="TOTAL_PASSED"), fmt="cades",
              contentType="Enveloped"),
         sign("cades-attributes", "Commitment type, signer location, roles, content hints, MIME type", ["CA-2", CADES, "attributes"], signed("BB"), fmt="cades",
              commitment="ProofOfOrigin", signerCountry="PE", signerLocality="Lima", signerPostalAddress=["Av. Example 123"],
              signerRoles=["Legal representative"], mimeType="text/plain", contentDescription="Contract"),
         sign("cades-policy", "Explicit signature policy (signature-policy-identifier, SPuri)", ["CA-2", CADES, "policy"], {"outcome": "signed"}, fmt="cades",
              kind="CustomPolicy", policyOid="1.3.6.1.4.1.99999.1.1", policyUri="https://example.org/policy.der"),
         sign("cades-policy-store", "Signature policy with the policy document embedded (signature-policy-store)", ["CA-8", "CA-2", CADES, "policy"],
              {"outcome": "signed"}, fmt="cades", kind="CustomPolicy", policyOid="1.3.6.1.4.1.99999.1.1", policyDocumentId="fixture:signature-policy"),
         sign("cades-certified-role", "Certified role (attribute certificate) and a signed SAML assertion", ["CA-2", CADES, "attributes"], signed("BB"),
              fmt="cades", attributeCertificateId="fixture:attribute-certificate", signedAssertionId="fixture:saml-assertion"),
         sign("cades-content-ts", "Content time-stamp before signing", ["CA-3", CADES, "tsa"], signed("BT"), fmt="cades", level="BT", timestamp=TSA,
              contentTimestamp=True),
         sign("cades-cosign", "Co-signature (a second, parallel signer)", ["CA-4", CADES], {"outcome": "signed"}, fmt="cades",
              operation="CoSign", existingSignatureId="step:cades-bb", credentialId="sandbox:rsa-3072"),
         sign("cades-countersign", "Countersignature of the first signer", ["CA-4", CADES], {"outcome": "signed"}, fmt="cades",
              operation="CounterSign", existingSignatureId="step:cades-bb", signerIndex=0, credentialId="sandbox:ecdsa-p256"),
         validate("cades-tree", "Validate co-signers and a countersignature", ["CA-4", CADES, VAL], "cades-sample:v-tree", {"outcome": "valid"}),
     ]},
    {"id": "xades", "title": "XAdES baseline (EN 319 132-1)",
     "description": "Enveloped, enveloping and detached; the optional signed properties, the data-objects time-stamp, countersignatures and the four levels.",
     "steps": [
         *levels("xades", ("XA-1", "XA-6", "XA-7", "XA-8")),
         *[sign(f"xades-{form.lower()}", f"XAdES B-B, {form.lower()}", ["XA-1", XADES], signed("BB", indication="TOTAL_PASSED"), fmt="xades", form=form)
           for form in ("Enveloping", "Detached")],
         sign("xades-v1", "XAdES 1.3.2 SigningCertificate (V1)", ["XA-1", XADES], signed("BB"), fmt="xades", signingCertificateV1=True),
         sign("xades-attributes", "Commitment type, roles, production place, data object format", ["XA-2", XADES, "attributes"], signed("BB"), fmt="xades",
              commitment="ProofOfApproval", signerRoles=["Legal representative"], placeCity="Lima", placeCountry="PE", mimeType="application/xml"),
         sign("xades-policy", "Explicit signature policy (SignaturePolicyIdentifier)", ["XA-2", XADES, "policy"], {"outcome": "signed"}, fmt="xades",
              kind="CustomPolicy", policyOid="1.3.6.1.4.1.99999.1.1", policyUri="https://example.org/policy.der"),
         sign("xades-policy-store", "SignaturePolicyStore with the policy document", ["XA-2", XADES, "policy"], {"outcome": "signed"}, fmt="xades",
              kind="CustomPolicy", policyOid="1.3.6.1.4.1.99999.1.1", policyDocumentId="fixture:signature-policy"),
         sign("xades-certified-role", "SignerRoleV2 with a certified role and a signed SAML assertion", ["XA-2", XADES, "attributes"], signed("BB"),
              fmt="xades", attributeCertificateId="fixture:attribute-certificate", signedAssertionId="fixture:saml-assertion"),
         sign("xades-data-ts", "AllDataObjectsTimeStamp", ["XA-3", XADES, "tsa"], signed("BT"), fmt="xades", level="BT", timestamp=TSA,
              dataObjectsTimestamp=True),
         sign("xades-countersign", "CounterSignature", ["XA-5", XADES], {"outcome": "signed"}, fmt="xades", dataId="step:xades-bb", counterSign=True,
              credentialId="sandbox:ecdsa-p256"),
         sign("xades-inclusive", "Inclusive canonicalization", ["XA-9", XADES], signed("BB", indication="TOTAL_PASSED"), fmt="xades",
              canonicalization="Inclusive"),
     ]},
    {"id": "algorithms", "title": "Keys and digests (all formats)", "steps": [
        *[sign(f"{f}-{c}", f"{f.upper()} with {c.upper()}", ["AL-1", "CE-1", STD[f], CRYPTO], signed("BB", indication="TOTAL_PASSED"), fmt=f,
               credentialId=f"sandbox:{c}")
          for f in ("pades", "cades", "xades") for c in ("rsa-4096", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521")],
        *[sign(f"{f}-pss", f"{f.upper()} with RSASSA-PSS", ["AL-1", STD[f], CRYPTO], signed("BB", indication="TOTAL_PASSED"), fmt=f, padding="Pss")
          for f in ("pades", "cades", "xades")],
        *[sign(f"{f}-{h.lower()}", f"{f.upper()} with {h.replace('_', '-').upper()}", ["AL-2", STD[f], CRYPTO], signed("BB", indication="TOTAL_PASSED"),
               fmt=f, hash=h)
          for f in ("pades", "cades", "xades") for h in ("Sha384", "Sha512")],
        sign("rsa-1024", "RSA 1024 key: refused", ["AL-1", "CE-3", CRYPTO], refused("KeyTooWeak"), credentialId="sandbox:rsa-1024"),
        sign("chain-sha1", "Chain with a CA signed with SHA-1: refused", ["CE-3", CRYPTO], refused("AlgorithmNotPermitted"),
             credentialId="sandbox:under-sha1-ca", signingPolicyId="preset:signing:iofe", signingControls={"trust": ["SandboxRoot"]}),
        sign("level-not-reached", "B-T with the TSA down: refused", ["AL-4", PADES, "tsa"], refused(), sandbox={"tsa": "Down"}, level="BT", timestamp=TSA),
        sign("level-lower", "B-T with the TSA down, lower level allowed: B-B", ["AL-4", PADES, "tsa"], signed("BB"), sandbox={"tsa": "Down"}, level="BT",
             timestamp=TSA, returnLowerLevel=True),
    ]},
    {"id": "extended", "title": "Extended forms (EN 319 122-2, EN 319 132-2)", "steps": [
        *[sign(f"{f}-ext-{name}", f"{f.upper()} {label}", [item, "EN 319 122-2" if f == "cades" else "EN 319 132-2", "extended"], {"outcome": "signed"},
               fmt=f, level="BT", timestamp=TSA, extendedForm=form)
          for f, item in (("cades", "EX-1"), ("xades", "EX-2"))
          for name, label, form in (("c", "-C (complete references)", "CompleteReferences"), ("xl", "-X-L", "ExtendedLong"), ("a", "-A (archive)", "Archive"))],
    ]},
    {"id": "augment", "title": "Augmentation (raising an existing signature's level)",
     "description": "A B-B signature made above is raised one level at a time with the library's augmenters (PadesAugmenter, CadesAugmenter, "
                    "XadesAugmenter); each result is validated. The PAdES B-LTA is then renewed with a new document time-stamp.",
     "steps": [
         *chain("pades", PADES),
         augment("aug-pades-renew", "PAdES: renew the archive time-stamp", ["PA-6", PADES, "augment"], "step:aug-pades-blta", "BLTA", renew=True,
                 desc="The validation data of the last document time-stamp, then a new document time-stamp over it."),
         *chain("cades", CADES, data_id="cades-sample:text"),
         *chain("xades", XADES),
     ]},
    {"id": "timestamps", "title": "Time-stamps (RFC 3161, EN 319 422)", "steps": [
        sign("ts-invalid-token", "Token with an invalid signature: refused", ["TS-1", TSP, "tsa"], refused(), sandbox={"tsa": "InvalidToken"}, level="BT",
             timestamp=TSA),
        *[sign(f"ts-{name}", f"TSA {label}: refused", ["TS-2", TSP, "tsa"], refused(reason), level="BT", timestamp={"provider": provider},
               signingPolicyId="preset:signing:iofe", signingControls={"trust": ["SandboxRoot"]})
          for name, label, provider, reason in (("revoked", "certificate revoked", "SandboxRevoked", "TimestampCertificateRevoked"),
                                                ("expired", "certificate expired", "SandboxExpired", "TimestampCertificateNotValid"),
                                                ("untrusted", "outside the anchors", "SandboxUntrusted", "TimestampUntrusted"))],
        sign("ts-expected", "Expected TSA", ["TS-3", TSP, "tsa"], signed("BT"), level="BT", timestamp=TSA,
             signingControls={"trust": ["SandboxRoot"], "expectedTsa": "tsa"}),
        sign("ts-unexpected", "Another TSA than expected: refused", ["TS-3", TSP, "tsa"], refused("TimestampUntrusted"), level="BT", timestamp=TSA,
             signingPolicyId="preset:signing:iofe", signingControls={"trust": ["SandboxRoot"], "expectedTsa": "tsa-revoked"}),
        validate("ts-profile-ok", "Time-stamp with the EN 319 422 profile", ["TS-6", "EN 319 422", "tsa"], "step:cades-bt",
                 {"outcome": "valid", "indication": "TOTAL_PASSED"}, data_id="cades-sample:text", policyId="fixture:validation-policy-en319422",
                 desc="The Sandbox TSA gives its accuracy, does not claim ordering and uses the policy the validation policy accepts."),
        validate("ts-profile-no-accuracy", "Time-stamp without accuracy, under the EN 319 422 profile", ["TS-6", "EN 319 422", "tsa"],
                 "cades-sample:v-no-accuracy", {"outcome": "valid", "failedConstraints": ["AccuracyPresent"]},
                 data_id="cades-sample:v-no-accuracy#data", policyId="fixture:validation-policy-en319422",
                 desc="The time-stamp fails AccuracyPresent, so it is not used as a proof of existence (EN 319 102-1); the signature itself, "
                      "with a valid certificate, still passes."),
        sign("ts-authenticated", "Authenticated TSA (HTTP Basic)", ["TS-4", TSP, "tsa"], signed("BT"), level="BT",
             timestamp={"provider": "SandboxAuthenticated"}),
    ]},
    {"id": "validation", "title": "Validation (EN 319 102-1)",
     "description": "Each case must give its indication and sub-indication. Files come from samples or from the signing steps above.",
     "steps": [
         validate("va-valid-pades", "Intact PAdES", ["VA-1", "VA-20", "VA-21", VAL, "TS 119 102-2"], "sample:valid",
                  {"outcome": "valid", "indication": "TOTAL_PASSED", "etsiReport": "valid"}),
         validate("va-valid-cades", "Intact CAdES (detached)", ["VA-1", "VA-21", VAL], "cades-sample:v-valid", {"outcome": "valid", "indication": "TOTAL_PASSED"},
                  data_id="cades-sample:v-valid#data"),
         validate("va-valid-xades", "Intact XAdES", ["VA-1", "VA-21", VAL], "xades-sample:v-xades", {"outcome": "valid", "indication": "TOTAL_PASSED"}),
         validate("va-hash-pades", "PDF content changed", ["VA-2", VAL], "sample:tampered-content",
                  {"outcome": "invalid", "indication": "TOTAL_FAILED", "subIndication": "HASH_FAILURE"}),
         validate("va-hash-cades", "CAdES data changed", ["VA-2", VAL], "cades-sample:v-changed-data",
                  {"outcome": "invalid", "indication": "TOTAL_FAILED", "subIndication": "HASH_FAILURE"}, data_id="cades-sample:v-changed-data#data"),
         validate("va-hash-xades", "XAdES document changed", ["VA-2", VAL], "xades-sample:v-changed",
                  {"outcome": "invalid", "indication": "TOTAL_FAILED", "subIndication": "HASH_FAILURE"}),
         validate("va-sig-pades", "PDF signature value changed", ["VA-3", VAL], "sample:tampered-cms",
                  {"outcome": "invalid", "indication": "TOTAL_FAILED", "subIndication": "SIG_CRYPTO_FAILURE"}),
         validate("va-sig-cades", "CAdES signature value changed", ["VA-3", VAL], "cades-sample:v-tampered",
                  {"outcome": "invalid", "indication": "TOTAL_FAILED", "subIndication": "SIG_CRYPTO_FAILURE"}, data_id="cades-sample:v-tampered#data"),
         validate("va-sig-xades", "XAdES signature value changed", ["VA-3", VAL], "xades-sample:v-tampered",
                  {"outcome": "invalid", "indication": "TOTAL_FAILED", "subIndication": "SIG_CRYPTO_FAILURE"}),
         validate("va-untrusted", "Root outside the anchors", ["VA-4", VAL], "sample:untrusted-root",
                  {"outcome": "indeterminate", "indication": "INDETERMINATE", "subIndication": "NO_CERTIFICATE_CHAIN_FOUND"}),
         validate("va-revoked", "Signer revoked, no POE before it", ["VA-5", "VA-20", VAL, "TS 119 102-2"], "sample:revoked",
                  {"outcome": "indeterminate", "indication": "INDETERMINATE", "subIndication": "REVOKED_NO_POE", "etsiReport": "valid"}),
         sign("va-poe-file", "B-T signature, then its signer is revoked", ["VA-6", PADES], signed("BT"), level="BT", timestamp=TSA,
              credentialId="sandbox:rsa-3072"),
         validate("va-revoked-after-poe", "Revoked after the signature time-stamp", ["VA-6", VAL, "revocation"], "step:va-poe-file",
                  {"outcome": "valid", "indication": "TOTAL_PASSED"}, sandbox={"revoke": ["rsa-3072"]}, wait=2,
                  desc="The signature time-stamp is a proof of existence before the revocation: the signature stays valid."),
         sign("va-short-lived-file", "B-LTA by a signer valid for 20 seconds", ["VA-9", PADES], signed("BLTA"), level="BLTA", timestamp=TSA,
              credentialId="sandbox-short-lived:20"),
         validate("va-expired-after-lta", "Signer expired after a valid B-LTA", ["VA-9", VAL], "step:va-short-lived-file",
                  {"outcome": "valid", "indication": "TOTAL_PASSED"}, wait=25,
                  desc="Validated after the signer's certificate expired: the signature time-stamp proves the signature existed while it was valid."),
         sign("va-revoked-ca", "Signer under a revoked CA: refused before signing", ["VA-7", VAL, "revocation"], refused("CertificateRevoked"),
              credentialId="sandbox:under-revoked-ca", signingPolicyId="preset:signing:strict"),
         validate("va-expired", "Signer expired, no POE", ["VA-8", VAL], "sample:expired",
                  {"outcome": "indeterminate", "indication": "INDETERMINATE", "subIndication": "OUT_OF_BOUNDS_NO_POE"}),
         sign("va-not-yet-valid", "Signer not yet valid: refused before signing", ["VA-10", VAL], refused("CertificateNotCurrentlyValid"),
              credentialId="sandbox:not-yet-valid"),
         validate("va-revocation-unknown", "Revocation status unknown (OCSP and CRL down)", ["VA-11", VAL, "revocation"], "step:pades-bb",
                  {"outcome": "indeterminate", "indication": "INDETERMINATE"}, sandbox={"ocsp": "Down", "crl": "Down"}),
         validate("va-timestamp-order", "Content time-stamp later than the signature time-stamp", ["VA-15", VAL], "cades-sample:v-ts-order",
                  {"outcome": "indeterminate", "indication": "INDETERMINATE", "subIndication": "TIMESTAMP_ORDER_FAILURE"},
                  data_id="cades-sample:v-ts-order#data", policyId="preset:validation:strict",
                  desc="Out-of-order time-stamps are a constraint of the validation policy (Timestamp/Coherence): the default only warns, the strict preset fails."),
         validate("va-wrong-cert-ref", "signing-certificate-v2 names another certificate", ["VA-16", VAL], "cades-sample:v-wrong-cert-ref",
                  {"outcome": "indeterminate", "indication": "INDETERMINATE", "subIndication": "NO_SIGNING_CERTIFICATE_FOUND"},
                  data_id="cades-sample:v-wrong-cert-ref#data"),
         validate("va-policy-not-available", "Signature policy whose document is not available", ["VA-14", VAL, "policy"], "step:cades-policy",
                  {"outcome": "indeterminate", "indication": "INDETERMINATE", "subIndication": "SIGNATURE_POLICY_NOT_AVAILABLE"},
                  data_id="cades-sample:text", policyId="preset:validation:strict",
                  desc="The signature names a policy but does not carry its document, and the validator has no way to obtain it: under a policy that requires it (PolicyAvailable FAIL)."),
         validate("va-policy-available", "Signature policy carried in the signature-policy-store", ["VA-14", "CA-8", VAL, "policy"], "step:cades-policy-store",
                  {"outcome": "valid", "indication": "TOTAL_PASSED"}, data_id="cades-sample:text", policyId="preset:validation:strict"),
         validate("va-signed-data-missing-cades", "Detached CAdES validated without its data", ["VA-17", VAL], "cades-sample:v-valid",
                  {"outcome": "indeterminate", "indication": "INDETERMINATE", "subIndication": "SIGNED_DATA_NOT_FOUND"}),
         validate("va-signed-data-missing-xades", "Detached XAdES validated without its data", ["VA-17", VAL], "xades-sample:v-detached",
                  {"outcome": "indeterminate", "indication": "INDETERMINATE", "subIndication": "SIGNED_DATA_NOT_FOUND"}),
         sign("va-weak-key-file", "RSA 1024 signature (minimal signing policy, to validate)", ["VA-12", CRYPTO], {"outcome": "signed"},
              credentialId="sandbox:rsa-1024", signingPolicyId="preset:signing:minimal"),
         validate("va-weak-key", "RSA 1024 against the crypto suite", ["VA-12", VAL, CRYPTO], "step:va-weak-key-file",
                  {"outcome": "indeterminate", "indication": "INDETERMINATE"}),
         sign("va-key-usage-file", "Signer with neither digitalSignature nor nonRepudiation (minimal signing policy, to validate)", ["VA-13"],
              {"outcome": "signed"}, credentialId="sandbox:no-signing-key-usage", signingPolicyId="preset:signing:minimal"),
         validate("va-key-usage", "Signer with neither digitalSignature nor nonRepudiation", ["VA-13", VAL], "step:va-key-usage-file", {"outcome": "indeterminate", "indication": "INDETERMINATE"},
                  policyId="preset:validation:iofe",
                  desc="The key usage a signer needs is a constraint of the validation policy (EN 319 102-1): the IOFE policy asks for digitalSignature or nonRepudiation."),
         # VA-9, full case: the signature time-stamp's TSA expires too; only the later archive time-stamp keeps its POE.
         *[step for fmt, data in (("pades", None), ("cades", "cades-sample:text")) for step in (
             sign(f"va-pastsig-{fmt}", f"{fmt[0].upper()}AdES B-T: signer valid 40 s, TSA certificate valid 30 s", ["VA-9", STD[fmt], "past signature"],
                  signed("BT"), fmt=fmt, level="BT", timestamp={"provider": "SandboxShortLived"}, credentialId="sandbox-short-lived:40"),
             augment(f"va-pastsig-{fmt}-lta", f"{fmt[0].upper()}AdES: archived at once with the long-lived TSA", ["VA-9", STD[fmt], "past signature"],
                     f"step:va-pastsig-{fmt}", "BLTA", data_id=data),
             validate(f"va-pastsig-{fmt}-valid", f"{fmt[0].upper()}AdES: signer and signature TSA expired, archive time-stamp valid",
                      ["VA-9", VAL, "past signature"], f"step:va-pastsig-{fmt}-lta", {"outcome": "valid", "indication": "TOTAL_PASSED"},
                      data_id=data, wait=45,
                      desc="Past signature validation (EN 319 102-1 §5.6): the archive time-stamp proves the signature time-stamp existed "
                           "while its TSA's certificate was valid, and that time-stamp proves the signature existed while the signer's was."))],
         sign("va-pastsig-bt-only", "B-T only: signer valid 40 s, TSA certificate valid 30 s", ["VA-9", PADES, "past signature"], signed("BT"),
              level="BT", timestamp={"provider": "SandboxShortLived"}, credentialId="sandbox-short-lived:40"),
         validate("va-pastsig-no-archive", "Signer and TSA expired, no archive time-stamp", ["VA-9", VAL, "past signature"],
                  "step:va-pastsig-bt-only", {"outcome": "indeterminate", "indication": "INDETERMINATE"}, wait=45,
                  desc="Nothing proves the signature time-stamp existed while its TSA's certificate was valid: no proof of existence."),
         *[validate(f"va-level-{lv.lower()}", f"B-LTA validated at level {lv}", ["VA-18", VAL], "step:pades-blta", {"outcome": "valid"}, level=lv)
           for lv in ("BasicSignatures", "Timestamps", "LongTermData", "ArchivalData")],
         sign("va-policy-file", "Signer without nonRepudiation (to validate)", ["VA-19"], {"outcome": "signed"}, credentialId="sandbox:no-nonrepudiation"),
         validate("va-policy", "A validation policy that requires nonRepudiation", ["VA-19", VAL, "TS 119 172-1"], "step:va-policy-file",
                  {"outcome": "indeterminate", "indication": "INDETERMINATE"}, policyId="playbook:requires-non-repudiation"),
     ]},
    {"id": "trusted-lists", "title": "Trusted lists (TS 119 612)", "steps": [
        sign("tl-ok", "Anchors from the Sandbox's trusted list", ["TL-1", TLS], signed("BB"), signingControls={"trust": ["SandboxTrustedList"]}),
        *[sign(f"tl-{f.lower()}", f"Trusted list {label}: refused", [item, TLS], refused("UntrustedRoot"), sandbox={"trustedList": f},
               signingControls={"trust": ["SandboxTrustedList"]})
          for f, label, item in (("Expired", "expired", "TL-2"), ("WrongSigner", "signed by another key", "TL-3"), ("Tampered", "tampered", "TL-4"))],
        validate("va-tl-ok", "Validate with anchors from the trusted list", ["TL-1", TLS, VAL], "step:tl-ok", {"outcome": "valid"}, trust=["SandboxTrustedList"]),
        validate("va-tl-wrong-signer", "Validate with a fake trusted list", ["TL-3", TLS, VAL], "step:tl-ok", {"outcome": "indeterminate"},
                 sandbox={"trustedList": "WrongSigner"}, trust=["SandboxTrustedList"]),
        *[step for fmt in ("pades", "xades") for step in (
            sign(f"tl-history-{fmt}", f"{fmt[0].upper()}AdES B-T while the root CA's service is granted", ["TL-5", TLS, STD[fmt]], signed("BT"),
                 fmt=fmt, level="BT", timestamp=TSA, signingControls={"trust": ["SandboxTrustedList"]}),
            validate(f"va-tl-history-{fmt}", f"{fmt[0].upper()}AdES: service withdrawn after the signature time-stamp", ["TL-5", TLS, VAL, "TS 119 615"],
                     f"step:tl-history-{fmt}", {"outcome": "valid", "indication": "TOTAL_PASSED"}, wait=2,
                     sandbox={"trustedList": "WithdrawnAfterUse"}, trust=["SandboxTrustedList"],
                     desc="The trusted list now says withdrawn, with granted in the service history before: the anchors at the time-stamp's time vouch for the signature."))],
        sign("tl-withdrawn", "Signing after the service was withdrawn: refused", ["TL-5", TLS], refused("UntrustedRoot"),
             sandbox={"trustedList": "WithdrawnAfterUse"}, signingControls={"trust": ["SandboxTrustedList"]}, signingPolicyId="preset:signing:anchored",
             desc="A signing policy that asks for a chain to the anchors: the root CA's service is withdrawn now."),
    ]},
]

playbook = {
    "$schema": "https://raw.githubusercontent.com/eupassarin/SimpleSign/main/docs/schemas/playbook.schema.json",
    "schema": 2,
    "id": "etsi-baseline",
    "title": "ETSI baseline signatures and validation",
    "description": "What docs/playbooks/etsi-checklist.md marks as shown by a run: PAdES, CAdES and XAdES baseline signatures (EN 319 142-1, "
                   "EN 319 122-1, EN 319 132-1), the extended forms, time-stamps, EN 319 102-1 validation and trusted lists, against the Sandbox, "
                   "cross-validated with EU DSS when one is connected. Tags name the checklist items and the standards.",
    "defaults": {
        "engine": "library",
        "format": "pades",
        "crossValidate": True,
        "options": {
            "common": {"level": "BB", "credentialId": "sandbox:rsa-2048", "attemptRefused": True,
                       "validation": {"trust": ["Sandbox"]}},
            "pades": {"documentId": "sample:contract"},
        },
    },
    # A validation policy that requires the nonRepudiation bit (VA-19): the default one with that constraint changed.
    "policies": [{"id": "requires-non-repudiation", "kind": "validation", "base": "default",
                  "set": {"SignatureConstraints/BasicSignatureConstraints/SigningCertificate/KeyUsage": {"Level": "FAIL", "Id": ["nonRepudiation"]}}}],
    "sections": sections,
}

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "docs/playbooks/etsi-baseline.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(playbook, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(sum(len(s["steps"]) for s in sections), "steps")
