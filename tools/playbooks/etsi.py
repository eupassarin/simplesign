"""Writes docs/playbooks/etsi-baseline.json: the steps of docs/playbooks/etsi-checklist.md a run can show, against the
TestBench's Sandbox.

Every step is tagged with the checklist items it covers (PA-n PAdES, CA-n CAdES, XA-n XAdES, AL-n all formats, EX-n
extended forms, TS-n time-stamps, VA-n validation, TL-n trusted lists, CE-n certificates) and the ETSI standard.
Items marked N or X in the checklist are not here.

    python3 tools/playbooks/etsi.py docs/playbooks/etsi-baseline.json
"""
import json
import sys

from describe import describe

PADES, CADES, XADES = "EN 319 142-1", "EN 319 122-1", "EN 319 132-1"
VAL, TSP, TLS, CRYPTO = "EN 319 102-1", "RFC 3161", "TS 119 612", "TS 119 312"
STD = {"pades": PADES, "cades": CADES, "xades": XADES}
FMT = {"pades": {}, "cades": {"dataId": "cades-sample:text"}, "xades": {"dataId": "xades-sample:order"}}
TSA = {"provider": "Sandbox"}
# The checks before signing that the default policy leaves out (revocation of the chain, the chain to the anchors, CRLs with
# nextUpdate, the CA certificates' algorithms, the TSA's certificate): a generic policy, the same as sandbox-basics' sandbox-strict.
STRICT_CHECKS = "playbook:strict-checks"
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
             credentialId="sandbox:under-sha1-ca", signingPolicyId=STRICT_CHECKS, signingControls={"trust": ["SandboxRoot"]}),
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
               signingPolicyId=STRICT_CHECKS, signingControls={"trust": ["SandboxRoot"]})
          for name, label, provider, reason in (("revoked", "certificate revoked", "SandboxRevoked", "TimestampCertificateRevoked"),
                                                ("expired", "certificate expired", "SandboxExpired", "TimestampCertificateNotValid"),
                                                ("untrusted", "outside the anchors", "SandboxUntrusted", "TimestampUntrusted"))],
        sign("ts-expected", "Expected TSA", ["TS-3", TSP, "tsa"], signed("BT"), level="BT", timestamp=TSA,
             signingControls={"trust": ["SandboxRoot"], "expectedTsa": "tsa"}),
        sign("ts-unexpected", "Another TSA than expected: refused", ["TS-3", TSP, "tsa"], refused("TimestampUntrusted"), level="BT", timestamp=TSA,
             signingPolicyId=STRICT_CHECKS, signingControls={"trust": ["SandboxRoot"], "expectedTsa": "tsa-revoked"}),
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
                  policyId="playbook:requires-key-usage",
                  desc="The key usage a signer needs is a constraint of the validation policy (EN 319 102-1): this one (playbook:requires-key-usage) "
                       "asks for digitalSignature or nonRepudiation."),
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


# What each step runs and why, for the steps above that give no desc (describe.py puts them in place).
DESCRIPTIONS = {
    "pades-bb":
        "Signs the sample contract in PAdES B-B (ETSI.CAdES.detached, signing-certificate-v2, no time-stamp) and "
        "validates it right after: the baseline every other level builds on.",
    "pades-bt":
        "PAdES B-T: B-B plus a signature time-stamp from the Sandbox's TSA, a proof the signature existed at that time.",
    "pades-blt":
        "PAdES B-LT: B-T plus the certificates, CRLs and OCSP responses in the DSS (and VRI), so the signature can be "
        "validated without fetching anything.",
    "pades-blta":
        "PAdES B-LTA: B-LT plus a document time-stamp over the DSS, which keeps the validation data trustworthy after "
        "the certificates expire. Its file is validated at each validation level below.",
    "pades-blta-archive-tsa":
        "B-LTA with the document time-stamp taken from a TSA configured apart from the signature time-stamp's, as a "
        "preservation service with its own TSA would.",
    "pades-certified-1":
        "A certification signature with DocMDP P=1: no change at all is allowed after it.",
    "pades-certified-2":
        "Certification with DocMDP P=2: only filling form fields and signing are allowed afterwards.",
    "pades-certified-3":
        "Certification with DocMDP P=3: form filling, signing and annotations are allowed afterwards.",
    "pades-attributes":
        "Writes the optional Reason and Location entries of the signature dictionary, to show they are kept and read "
        "back.",
    "pades-policy":
        "Writes an explicit signature-policy-identifier (OID, hash of the policy document, SPuri), as a policy-based "
        "signature (EN 319 142-1 'PAdES with policy') does.",
    "pades-pdfa":
        "Signs a PDF/A while preserving its conformance: the incremental update must not add anything PDF/A forbids.",
    "cades-bb":
        "Signs the sample text in CAdES B-B (detached, signing-certificate-v2, signing-time) and validates it with the "
        "data. Its file is reused by the co-signature, the countersignature and the augmentation steps.",
    "cades-bt":
        "CAdES B-T: B-B plus a signature time-stamp in the unsigned attributes. Its time-stamp is also checked against "
        "the EN 319 422 profile further down.",
    "cades-blt":
        "CAdES B-LT: B-T plus the certificates and revocation data needed to validate it offline, carried in the "
        "signature.",
    "cades-blta":
        "CAdES B-LTA: B-LT plus an archive-time-stamp-v3 with its ATSHashIndex.",
    "cades-attached":
        "CAdES B-B with the content inside the SignedData (a .p7m): the attached form, besides the detached one.",
    "cades-attributes":
        "Writes the optional signed attributes: commitment type (proof of origin), signer location, signer role, "
        "content hints and the MIME type.",
    "cades-policy":
        "Writes a signature-policy-identifier with only the policy OID and its SPuri (no document carried): the file "
        "va-policy-not-available validates.",
    "cades-policy-store":
        "Writes the signature policy with its document embedded (signature-policy-store), so a validator can check it "
        "without fetching it: the file va-policy-available validates.",
    "cades-certified-role":
        "Writes a signer-attributes-v2 with a certified role (an attribute certificate) and a signed SAML assertion, "
        "the two forms of claimed authority beyond a plain role.",
    "cades-content-ts":
        "Time-stamps the content before signing (content-time-stamp attribute), proving the data existed before the "
        "signature, besides the signature time-stamp.",
    "cades-cosign":
        "Adds a second, parallel signer (RSA 3072) to the CAdES B-B file: a SignedData with two SignerInfos over the "
        "same content.",
    "cades-countersign":
        "Countersigns the first signer of the CAdES B-B file with an ECDSA P-256 key: the countersignature signs the "
        "first signature value, not the content.",
    "cades-tree":
        "Validates a sample with co-signers and a countersignature: every signature in the tree must be found and "
        "verified.",
    "xades-bb":
        "Signs the sample XML order in XAdES B-B (enveloped, SigningCertificateV2, SigningTime) and validates it. Its "
        "file is countersigned and augmented below.",
    "xades-bt":
        "XAdES B-T: B-B plus a SignatureTimeStamp.",
    "xades-blt":
        "XAdES B-LT: B-T plus CertificateValues and RevocationValues, so it can be validated offline.",
    "xades-blta":
        "XAdES B-LTA: B-LT plus an ArchiveTimeStamp over the signature and its validation data.",
    "xades-enveloping":
        "XAdES B-B enveloping: the XML document goes inside the signature's ds:Object.",
    "xades-detached":
        "XAdES B-B detached: the signature references the document from outside and is validated with it.",
    "xades-v1":
        "Writes the XAdES 1.3.2 SigningCertificate (V1, with IssuerSerial) instead of V2, for verifiers that only read "
        "the older property.",
    "xades-attributes":
        "Writes the optional signed properties: CommitmentTypeIndication (proof of approval), SignerRoleV2, "
        "SignatureProductionPlaceV2 and DataObjectFormat (MIME type).",
    "xades-policy":
        "Writes a SignaturePolicyIdentifier with the policy OID and its SPURI qualifier (no document carried).",
    "xades-policy-store":
        "Writes a SignaturePolicyStore with the policy document, so a validator can check the policy without fetching "
        "it.",
    "xades-certified-role":
        "Writes SignerRoleV2 with a certified role (an attribute certificate) and a signed SAML assertion.",
    "xades-data-ts":
        "Adds an AllDataObjectsTimeStamp over the signed data, besides the signature time-stamp.",
    "xades-countersign":
        "Countersigns the XAdES B-B file with an ECDSA P-256 key (a CounterSignature unsigned property that signs the "
        "first SignatureValue).",
    "xades-inclusive":
        "Signs using inclusive canonicalization (C14N 1.0) instead of exclusive, to show both are produced and verify.",
    "pades-rsa-4096":
        "PAdES with an RSA 4096 key, validated right after.",
    "pades-ecdsa-p256":
        "PAdES with ECDSA on P-256 (with SHA-256).",
    "pades-ecdsa-p384":
        "PAdES with ECDSA on P-384 (with SHA-384).",
    "pades-ecdsa-p521":
        "PAdES with ECDSA on P-521 (with SHA-512).",
    "cades-rsa-4096":
        "CAdES with an RSA 4096 key.",
    "cades-ecdsa-p256":
        "CAdES with ECDSA on P-256.",
    "cades-ecdsa-p384":
        "CAdES with ECDSA on P-384.",
    "cades-ecdsa-p521":
        "CAdES with ECDSA on P-521.",
    "xades-rsa-4096":
        "XAdES with an RSA 4096 key.",
    "xades-ecdsa-p256":
        "XAdES with ECDSA on P-256 (with SHA-256).",
    "xades-ecdsa-p384":
        "XAdES with ECDSA on P-384.",
    "xades-ecdsa-p521":
        "XAdES with ECDSA on P-521.",
    "pades-pss":
        "PAdES with RSASSA-PSS padding instead of PKCS#1 v1.5 (the RSASSA-PSS parameters written in the SignerInfo).",
    "cades-pss":
        "CAdES with RSASSA-PSS padding.",
    "xades-pss":
        "XAdES with RSASSA-PSS (the XML DSig 1.1 rsa-pss URI).",
    "pades-sha384":
        "PAdES with SHA-384 as the digest of the document and of the signed attributes.",
    "pades-sha512":
        "PAdES with SHA-512.",
    "cades-sha384":
        "CAdES with SHA-384.",
    "cades-sha512":
        "CAdES with SHA-512.",
    "xades-sha384":
        "XAdES with SHA-384 for the references and the signature.",
    "xades-sha512":
        "XAdES with SHA-512.",
    "rsa-1024":
        "An RSA 1024 key, below what the default policy allows: refused before signing (KeyTooWeak).",
    "chain-sha1":
        "A certificate under a CA signed with SHA-1, with a signing policy that checks the algorithms of the CA "
        "certificates (playbook:strict-checks): SHA-1 in the chain is refused (AlgorithmNotPermitted).",
    "level-not-reached":
        "Asks for B-T while the TSA is down: the requested level cannot be reached, so the signer fails instead of "
        "silently returning B-B.",
    "level-lower":
        "Same, but the caller allows a lower level (returnLowerLevel): the signature is made at B-B and says it is not "
        "the level asked.",
    "cades-ext-c":
        "CAdES -C: a B-T signature plus complete-certificate-references and complete-revocation-references (references "
        "only, the values are not carried).",
    "cades-ext-xl":
        "CAdES -X-L: -C plus the certificate and revocation values themselves.",
    "cades-ext-a":
        "CAdES -A: -X-L plus an archive time-stamp.",
    "xades-ext-c":
        "XAdES -C: CompleteCertificateRefs and CompleteRevocationRefs after the signature time-stamp.",
    "xades-ext-xl":
        "XAdES -X-L: -C plus CertificateValues and RevocationValues.",
    "xades-ext-a":
        "XAdES -A: -X-L plus an ArchiveTimeStamp.",
    "aug-pades-bt":
        "Raises the PAdES B-B signature to B-T by adding a document time-stamp in an incremental update (EN 319 142-1 "
        "accepts it for level T), without signing again.",
    "aug-pades-blt":
        "Raises the B-T file to B-LT by adding the DSS with the validation data.",
    "aug-pades-blta":
        "Raises the B-LT file to B-LTA with a document time-stamp over the DSS.",
    "aug-cades-bt":
        "Raises the CAdES B-B signature to B-T by adding a signature time-stamp to the unsigned attributes (the "
        "detached data is given to rebuild the digest).",
    "aug-cades-blt":
        "Raises the CAdES B-T file to B-LT by adding the certificate and revocation values.",
    "aug-cades-blta":
        "Raises the CAdES B-LT file to B-LTA with an archive-time-stamp-v3.",
    "aug-xades-bt":
        "Raises the XAdES B-B signature to B-T by adding a SignatureTimeStamp to the unsigned properties.",
    "aug-xades-blt":
        "Raises the XAdES B-T file to B-LT with CertificateValues and RevocationValues.",
    "aug-xades-blta":
        "Raises the XAdES B-LT file to B-LTA with an ArchiveTimeStamp.",
    "ts-invalid-token":
        "The TSA answers a token whose signature does not verify: the signer must detect it and refuse instead of "
        "embedding it.",
    "ts-revoked":
        "With a signing policy that checks the TSA (playbook:strict-checks), a TSA whose certificate is revoked: its "
        "token is refused (TimestampCertificateRevoked).",
    "ts-expired":
        "A TSA whose certificate has expired: its token is refused (TimestampCertificateNotValid).",
    "ts-untrusted":
        "A TSA that chains to no anchor: its token is refused (TimestampUntrusted).",
    "ts-expected":
        "Names the Sandbox's TSA as the expected one (expectedTsa): the token comes from it, so the signature is made.",
    "ts-unexpected":
        "Expects another TSA than the one that answers: refused (TimestampUntrusted), so a token from an authority the "
        "signer did not choose is never embedded.",
    "ts-authenticated":
        "Gets the time-stamp from the TSA endpoint that requires HTTP Basic authentication.",
    "va-valid-pades":
        "Validates the intact PAdES sample: TOTAL_PASSED, and the ETSI TS 119 102-2 report must be valid against its "
        "XML schema.",
    "va-valid-cades":
        "Validates an intact detached CAdES sample with its data: TOTAL_PASSED.",
    "va-valid-xades":
        "Validates an intact XAdES sample: TOTAL_PASSED.",
    "va-hash-pades":
        "Validates the PDF whose content changed after signing: the ByteRange digest does not match, TOTAL_FAILED / "
        "HASH_FAILURE.",
    "va-hash-cades":
        "Validates a detached CAdES signature against data that changed: TOTAL_FAILED / HASH_FAILURE.",
    "va-hash-xades":
        "Validates an XAdES file whose signed document changed: a reference digest fails, TOTAL_FAILED / HASH_FAILURE.",
    "va-sig-pades":
        "Validates the PDF whose signature value was changed: digests match but the signature does not verify, "
        "TOTAL_FAILED / SIG_CRYPTO_FAILURE.",
    "va-sig-cades":
        "Validates a CAdES signature whose value was changed: SIG_CRYPTO_FAILURE.",
    "va-sig-xades":
        "Validates an XAdES signature whose SignatureValue was changed: SIG_CRYPTO_FAILURE.",
    "va-untrusted":
        "Validates the sample whose chain ends at a root outside the anchors: INDETERMINATE / "
        "NO_CERTIFICATE_CHAIN_FOUND.",
    "va-revoked":
        "Validates the sample signed by a revoked certificate, without a time-stamp before the revocation: "
        "INDETERMINATE / REVOKED_NO_POE, and the ETSI report must still be schema-valid.",
    "va-poe-file":
        "Signs at B-T with the RSA 3072 certificate: the signature time-stamp is the proof of existence the next step "
        "relies on when it revokes the certificate.",
    "va-short-lived-file":
        "Signs at B-LTA with a certificate the Sandbox issues valid for 20 seconds, so the next step can validate it "
        "after the certificate has expired.",
    "va-revoked-ca":
        "With the strict signing policy, a signer under a revoked CA: the chain's revocation is checked before signing, "
        "so it is refused (CertificateRevoked).",
    "va-expired":
        "Validates the sample signed by an expired certificate with no proof of existence: INDETERMINATE / "
        "OUT_OF_BOUNDS_NO_POE.",
    "va-not-yet-valid":
        "A certificate whose notBefore is in the future: refused before signing (CertificateNotCurrentlyValid), so no "
        "such file can be produced.",
    "va-revocation-unknown":
        "Validates the PAdES B-B file while the Sandbox's OCSP and CRL are both down: the status cannot be established, "
        "so INDETERMINATE instead of valid.",
    "va-wrong-cert-ref":
        "Validates a CAdES sample whose signing-certificate-v2 points to a certificate other than the signer's: the "
        "signer cannot be identified, NO_SIGNING_CERTIFICATE_FOUND.",
    "va-policy-available":
        "Validates the cades-policy-store file with the strict policy: the policy document travels in the "
        "signature-policy-store, so it can be checked and the signature is valid.",
    "va-signed-data-missing-cades":
        "Validates a detached CAdES signature without giving its data: nothing to compare the digest with, "
        "SIGNED_DATA_NOT_FOUND.",
    "va-signed-data-missing-xades":
        "Validates a detached XAdES signature without its document: SIGNED_DATA_NOT_FOUND.",
    "va-weak-key-file":
        "Signs with an RSA 1024 key under the minimal signing policy (which does not check key size), only to produce "
        "the file va-weak-key validates.",
    "va-weak-key":
        "Validates the RSA 1024 file: the cryptographic constraints of the validation policy reject the key size, so "
        "INDETERMINATE rather than valid.",
    "va-key-usage-file":
        "Signs with a certificate that has neither digitalSignature nor nonRepudiation under the minimal signing "
        "policy, only to produce the file va-key-usage validates.",
    "va-pastsig-pades":
        "PAdES B-T by a signer valid for 40 seconds, time-stamped by a TSA whose certificate is valid for 30: both will "
        "expire, to show past signature validation.",
    "va-pastsig-pades-lta":
        "Raises that file to B-LTA at once with the long-lived TSA: the archive time-stamp proves the signature and its "
        "time-stamp existed while their certificates were valid.",
    "va-pastsig-cades":
        "CAdES B-T by a signer valid for 40 seconds with a TSA certificate valid for 30, for the same past-signature "
        "case in CAdES.",
    "va-pastsig-cades-lta":
        "Raises the CAdES file to B-LTA at once with the long-lived TSA.",
    "va-pastsig-bt-only":
        "The same short-lived PAdES B-T, but never archived: the control case for va-pastsig-no-archive.",
    "va-level-basicsignatures":
        "Validates the PAdES B-LTA file at the BasicSignatures level of EN 319 102-1: signature, chain and revocation "
        "only.",
    "va-level-timestamps":
        "Validates it at the Timestamps level: the signature time-stamp is used as proof of existence too.",
    "va-level-longtermdata":
        "Validates it at the LongTermData level: the validation data embedded in the file is used.",
    "va-level-archivaldata":
        "Validates it at the ArchivalData level: the archive (document) time-stamp and past signature validation too.",
    "va-policy-file":
        "Signs with a certificate that has digitalSignature but not nonRepudiation (accepted by the default signing "
        "policy), to produce the file va-policy validates.",
    "va-policy":
        "Validates that file with a validation policy that requires nonRepudiation in the signing certificate's key "
        "usage: the constraint fails, INDETERMINATE.",
    "tl-ok":
        "Signs with the anchors read from the Sandbox's trusted list (its signature checked against the operator's "
        "certificate) instead of a configured root.",
    "tl-expired":
        "The trusted list is past its NextUpdate: it gives no anchors, so signing is refused (UntrustedRoot).",
    "tl-wrongsigner":
        "The trusted list is signed by a key other than its operator's: no anchors, signing refused.",
    "tl-tampered":
        "The trusted list changed after it was signed: its XML signature breaks, no anchors, signing refused.",
    "va-tl-ok":
        "Validates the tl-ok file with the anchors from the trusted list: valid.",
    "va-tl-wrong-signer":
        "Validates the same file while the list has another signer: no trusted anchors, INDETERMINATE.",
    "tl-history-pades":
        "Signs PAdES B-T while the list grants the root CA's service: the time-stamp is the proof of existence for the "
        "withdrawal step that follows.",
    "tl-history-xades":
        "Signs XAdES B-T while the root CA's service is granted, for the same withdrawal check in XAdES.",
}

# What each section above that gives no description shows.
SECTION_DESCRIPTIONS = {
    "algorithms":
        "Every format signs with each key type and digest the baseline profiles name (RSA 2048/4096, RSASSA-PSS, ECDSA "
        "P-256/P-384/P-521, SHA-256/384/512) and is validated right after; a weak key, a SHA-1 CA and a level that "
        "cannot be reached are refused.",
    "extended":
        "The extended forms of EN 319 122-2 (CAdES) and EN 319 132-2 (XAdES) that predate the baseline levels: -C "
        "(references to the validation data), -X-L (the values too) and -A (archive time-stamp), for readers that still "
        "expect them.",
    "timestamps":
        "The signature time-stamp obtained while signing is checked before it is kept (token signature, trust, validity "
        "and revocation of the TSA, the TSA the signer expects), and a validation policy can require the EN 319 422 "
        "time-stamp profile.",
    "trusted-lists":
        "Anchors taken from a TS 119 612 trusted list: a list that is expired, signed by another key or changed gives "
        "none; a service withdrawn after a time-stamp still vouches for that signature through the list's service "
        "history.",
}

sections = describe(sections, DESCRIPTIONS, SECTION_DESCRIPTIONS)

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
    "policies": [
        # A validation policy that requires the nonRepudiation bit (VA-19): the default one with that constraint changed.
        {"id": "requires-non-repudiation", "kind": "validation", "base": "default",
         "set": {"SignatureConstraints/BasicSignatureConstraints/SigningCertificate/KeyUsage": {"Level": "FAIL", "Id": ["nonRepudiation"]}}},
        # A validation policy that requires a key usage for signing (VA-13): digitalSignature or nonRepudiation.
        {"id": "requires-key-usage", "kind": "validation", "base": "default",
         "set": {"SignatureConstraints/BasicSignatureConstraints/SigningCertificate/KeyUsage": {"Level": "FAIL", "Id": ["digitalSignature", "nonRepudiation"]}}},
        {"id": "strict-checks", "kind": "signing", "base": "strict", "set": {"SigningCertificate/ProspectiveCertificateChain": {"Level": "FAIL"}, "SigningCertificate/CRLNextUpdatePresent": {"Level": "FAIL"}, "CACertificate/CRLNextUpdatePresent": {"Level": "FAIL"}, "CACertificate/Cryptographic": {"Level": "FAIL"}, "Timestamp/ProspectiveCertificateChain": {"Level": "FAIL"}, "Timestamp/NotExpired": {"Level": "FAIL"}, "Timestamp/NotRevoked": {"Level": "FAIL"}, "Timestamp/RevocationDataAvailable": {"Level": "FAIL"}}},
    ],
    "sections": sections,
}

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "docs/playbooks/etsi-baseline.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(playbook, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(sum(len(s["steps"]) for s in sections), "steps")
