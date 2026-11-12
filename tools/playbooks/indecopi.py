"""Writes docs/playbooks/indecopi-guia-v4.json: the automated steps that help with an INDECOPI (IOFE, Peru) software
accreditation (Guía de Acreditación de Software v4.0, annex B), run in the TestBench against the Sandbox.

Tags name the items of the guide each step helps with (F-n: signing by an automated agent, V-n: verification by
automated agents, S-n: time-stamp verification) and a topic. Items that need a person (manuals, code signing, the
cryptographic module) are not here: they are handled outside the playbook.

    python3 tools/playbooks/indecopi.py docs/playbooks/indecopi-guia-v4.json
"""
import json
import sys

FMT = {"pades": {}, "cades": {"dataId": "cades-sample:text"}, "xades": {"dataId": "xades-sample:order"}}


def sign(id, title, tags, expect, fmt="pades", desc=None, sandbox=None, **opts):
    s = {"id": id, "title": title, "tags": tags, "format": fmt, "options": {**FMT[fmt], **opts}, "expect": expect}
    if desc:
        s["description"] = desc
    if sandbox:
        s["sandbox"] = sandbox
    return s


def validate(id, title, tags, file_id, expect, desc=None, sandbox=None, data_id=None, **settings):
    options = {"fileId": file_id}
    if data_id:
        options["dataId"] = data_id
    options["settings"] = {"trust": ["Sandbox"], "policyId": "preset:validation:iofe", **settings}
    s = {"id": id, "kind": "validate", "title": title, "tags": tags, "options": options, "expect": expect}
    if desc:
        s["description"] = desc
    if sandbox:
        s["sandbox"] = sandbox
    return s


def refused(reason=None):
    return {"outcome": "refused", **({"reason": reason} if reason else {})}


TSL = {"trust": ["SandboxTrustedList"]}
TSA = {"provider": "Sandbox"}

sections = [
    {"id": "tsl", "title": "Trusted list (TSL)",
     "description": "The trust anchors come from the Sandbox's trusted list, whose signature is checked against the operator's certificate.",
     "steps": [
         sign("tsl-ok", "Sign with a root listed in the TSL", ["F-1", "F-3", "tsl"], {"outcome": "signed"}, signingControls=TSL,
              desc="The Sandbox's TSL is downloaded, its signature is checked with the operator's certificate, and the signer's root is listed: the signature is made."),
         sign("tsl-wrong-signer", "TSL signed by another key: refused", ["F-1", "tsl"], refused("UntrustedRoot"), sandbox={"trustedList": "WrongSigner"}, signingControls=TSL,
              desc="The Sandbox publishes a TSL signed by a key that is not the operator's (a fake TSL): there are no anchors and the signature is refused."),
         sign("tsl-tampered", "Tampered TSL: refused", ["F-1", "tsl"], refused("UntrustedRoot"), sandbox={"trustedList": "Tampered"}, signingControls=TSL),
         sign("tsl-expired", "Expired TSL: refused", ["F-2", "tsl"], refused("UntrustedRoot"), sandbox={"trustedList": "Expired"}, signingControls=TSL,
              desc="The published TSL has its NextUpdate in the past."),
         validate("v-tsl-ok", "Validate with anchors from the TSL", ["V-1", "V-3", "tsl"], "step:tsl-ok", {"outcome": "valid"}, trust=["SandboxTrustedList"]),
         # A list whose signature fails is not used: no anchor. An expired one is used, and IOFE's TLNotExpired (FAIL) judges it.
         validate("v-tsl-wrong-signer", "Validate with a fake TSL", ["V-1", "tsl"], "step:tsl-ok",
                  {"outcome": "indeterminate", "subIndication": "NO_CERTIFICATE_CHAIN_FOUND"},
                  sandbox={"trustedList": "WrongSigner"}, trust=["SandboxTrustedList"]),
         validate("v-tsl-expired", "Validate with an expired TSL", ["V-2", "tsl"], "step:tsl-ok",
                  {"outcome": "indeterminate", "subIndication": "TRY_LATER"},
                  sandbox={"trustedList": "Expired"}, trust=["SandboxTrustedList"]),
     ]},
    {"id": "revocation", "title": "Revocation before signing (CRL and OCSP)", "steps": [
        sign("crl-https-good", "CRL over HTTPS, good certificate", ["F-5", "F-8", "crl"], {"outcome": "signed"}, credentialId="sandbox:good-crl-https"),
        sign("crl-https-revoked", "CRL over HTTPS, revoked certificate: refused", ["F-5", "F-8", "crl"], refused("CertificateRevoked"), credentialId="sandbox:revoked-crl-https"),
        sign("crl-ldap-good", "CRL over LDAP, good certificate", ["F-5", "crl", "ldap"], {"outcome": "signed"}, credentialId="sandbox:good-crl-ldap"),
        sign("crl-ldap-revoked", "CRL over LDAP, revoked certificate: refused", ["F-5", "crl", "ldap"], refused("CertificateRevoked"), credentialId="sandbox:revoked-crl-ldap"),
        sign("crl-wrong-key", "CRL signed by another key: refused", ["F-6", "crl"], refused("RevocationStatusUnknown"), sandbox={"crl": "WrongKey"},
             credentialId="sandbox:good-crl-https",
             desc="The Sandbox signs the CRL with a key that is not the issuing CA's: the CRL is not accepted and, without OCSP, the status is unknown."),
        sign("crl-expired", "Expired CRL: refused", ["F-7", "crl"], refused("RevocationStatusUnknown"), sandbox={"crl": "Expired"}, credentialId="sandbox:good-crl-https"),
        sign("crl-no-next-update", "CRL without nextUpdate: refused", ["F-7", "crl"], refused("RevocationStatusUnknown"), sandbox={"crl": "NoNextUpdate"},
             credentialId="sandbox:good-crl-https",
             desc="A CRL without nextUpdate does not say until when it is current: the IOFE policy (CRLNextUpdatePresent) refuses it."),
        sign("crl-stale", "Revoked after the cached CRL: refused", ["F-8", "crl"], refused("CertificateRevoked"), sandbox={"crl": "Stale", "revoke": ["rsa-3072"]},
             credentialId="sandbox:rsa-3072",
             desc="The certificate is revoked now; before signing the status is fetched again (OCSP, then the CRL downloaded without cache), not the earlier copy."),
        sign("crl-down", "CRL server down, no OCSP: refused", ["F-8", "crl"], refused("RevocationStatusUnknown"), sandbox={"crl": "Down"}, credentialId="sandbox:good-crl-https"),
        validate("v-crl-wrong-key", "Validate with a CRL signed by another key", ["V-6", "crl"], "step:crl-https-good", {"outcome": "indeterminate"}, sandbox={"crl": "WrongKey"}),
        validate("v-crl-expired", "Validate with an expired CRL", ["V-7", "crl"], "step:crl-https-good", {"outcome": "indeterminate"}, sandbox={"crl": "Expired"}),
        sign("chain-revoked", "Certificate under a revoked CA: refused", ["F-9", "revocation"], refused("CertificateRevoked"), credentialId="sandbox:under-revoked-ca"),
        sign("ocsp-good", "OCSP, good certificate", ["F-10", "ocsp"], {"outcome": "signed"}, credentialId="sandbox:good-ocsp"),
        sign("ocsp-revoked", "OCSP, revoked certificate: refused", ["F-10", "ocsp"], refused("CertificateRevoked"), credentialId="sandbox:revoked-ocsp"),
        sign("ocsp-unauthorized", "OCSP response from an unauthorized signer, no CRL: refused", ["F-10", "ocsp"], refused("RevocationStatusUnknown"),
             sandbox={"ocsp": "Unauthorized"}, credentialId="sandbox:good-ocsp"),
    ]},
    {"id": "validity", "title": "Certificate validity and purpose", "steps": [
        sign("expired", "Expired certificate: refused", ["F-11", "validity"], refused("CertificateExpired"), credentialId="sandbox:expired"),
        sign("not-yet-valid", "Not yet valid certificate: refused", ["F-11", "validity"], refused("CertificateNotCurrentlyValid"), credentialId="sandbox:not-yet-valid"),
        sign("chain-expired", "Certificate under an expired CA: refused", ["F-11", "validity"], refused("ChainCertificateNotValid"), credentialId="sandbox:under-expired-ca"),
        sign("no-key-usage", "Neither digitalSignature nor nonRepudiation: refused", ["F-12", "key-usage"], refused("KeyUsageNotPermitted"), credentialId="sandbox:no-signing-key-usage"),
        sign("no-key-usage-extension", "No KeyUsage extension: refused", ["F-12", "key-usage"], refused("KeyUsageNotPermitted"), credentialId="sandbox:no-key-usage-extension"),
        *[sign(f"no-key-usage-{f}", f"{f.upper()}: neither digitalSignature nor nonRepudiation", ["F-12", "key-usage"], refused("KeyUsageNotPermitted"), fmt=f,
               credentialId="sandbox:no-signing-key-usage") for f in ("cades", "xades")],
        sign("signed-no-nonrepudiation", "Sign with a certificate without nonRepudiation (to validate)", ["F-12", "key-usage"], {"outcome": "signed"},
             credentialId="sandbox:no-nonrepudiation",
             desc="Signing accepts digitalSignature or nonRepudiation; the file is used by the validation step that requires nonRepudiation."),
        validate("v-no-nonrepudiation", "Validation requires nonRepudiation: not accepted", ["V-12", "key-usage"], "step:signed-no-nonrepudiation",
                 {"outcome": "indeterminate"}, policyId="preset:validation:iofe-nonrepudiation",
                 desc="With the iofe-nonrepudiation policy the certificate without nonRepudiation fails the chain constraint (EN 319 102-1: INDETERMINATE)."),
        validate("v-revoked", "Validate a revoked signer", ["V-5", "V-8", "V-9", "V-10", "revocation"], "sample:revoked", {"outcome": "indeterminate"},
                 desc="A sample signed by a certificate revoked afterwards: the validator checks the chain's CRL/OCSP and does not accept it."),
        validate("v-expired", "Validate an expired signer", ["V-11", "validity"], "sample:expired", {"outcome": "indeterminate"}),
        validate("v-untrusted", "Validate with a root outside the anchors", ["V-3", "trust"], "sample:untrusted-root", {"outcome": "indeterminate"}),
    ]},
    {"id": "timestamp", "title": "Time-stamps (RFC 3161)",
     "description": "Each time-stamp obtained while signing is checked: expected TSA, token signature, trust, validity and revocation of the TSA certificate.",
     "steps": [
         sign("tsa-ok", "Time-stamp from the Sandbox's TSA", ["S-1", "S-2", "S-3", "S-4", "F-31", "tsa"], {"outcome": "signed", "level": "B-T"}, level="BT", timestamp=TSA,
              signingControls={"trust": ["SandboxRoot"], "expectedTsa": "tsa"}),
         sign("tsa-unexpected", "Time-stamp from another TSA than expected: refused", ["S-1", "tsa"], refused("TimestampUntrusted"), level="BT", timestamp=TSA,
              signingControls={"trust": ["SandboxRoot"], "expectedTsa": "tsa-revoked"}),
         sign("tsa-invalid-token", "Token with an invalid signature: refused", ["S-2", "tsa"], refused(), sandbox={"tsa": "InvalidToken"}, level="BT", timestamp=TSA),
         sign("tsa-revoked", "Revoked TSA: refused", ["S-3", "tsa"], refused("TimestampCertificateRevoked"), level="BT", timestamp={"provider": "SandboxRevoked"}),
         sign("tsa-untrusted", "TSA outside the anchors: refused", ["S-1", "tsa"], refused("TimestampUntrusted"), level="BT", timestamp={"provider": "SandboxUntrusted"}),
         sign("tsa-expired", "TSA with an expired certificate: refused", ["S-4", "tsa"], refused("TimestampCertificateNotValid"), level="BT",
              timestamp={"provider": "SandboxExpired"},
              desc="The TSA certificate has expired: the time-stamp it issues now is not valid at its own time."),
         *[sign(f"tsa-revoked-{f}", f"{f.upper()}: revoked TSA", ["S-3", "tsa"], refused("TimestampCertificateRevoked"), fmt=f, level="BT",
                timestamp={"provider": "SandboxRevoked"}) for f in ("cades", "xades")],
         *[sign(f"tsa-expired-{f}", f"{f.upper()}: expired TSA", ["S-4", "tsa"], refused("TimestampCertificateNotValid"), fmt=f, level="BT",
                timestamp={"provider": "SandboxExpired"}) for f in ("cades", "xades")],
     ]},
    {"id": "levels", "title": "Validation data and levels (B-T, B-LT, B-LTA)", "steps": [
        *[sign(f"{f}-{lv.lower()}", f"{f.upper()} {lv[0]}-{lv[1:]}", ["F-31", "V-31", "levels"],
               {"outcome": "signed", "level": f"{lv[0]}-{lv[1:]}", "indication": "TOTAL_PASSED"}, fmt=f, level=lv, timestamp=TSA)
          for f in ("pades", "cades", "xades") for lv in ("BLT", "BLTA")],
        sign("cades-attached-blta", "CAdES attached (p7m) B-LTA", ["F-31", "V-31", "levels"], {"outcome": "signed", "level": "B-LTA"}, fmt="cades", level="BLTA",
             timestamp=TSA, contentType="Enveloped"),
        sign("xades-detached-blta", "XAdES detached B-LTA", ["F-31", "V-31", "levels"], {"outcome": "signed", "level": "B-LTA"}, fmt="xades", level="BLTA",
             timestamp=TSA, form="Detached"),
        sign("xades-enveloping-blta", "XAdES enveloping B-LTA", ["F-31", "V-31", "levels"], {"outcome": "signed", "level": "B-LTA"}, fmt="xades", level="BLTA",
             timestamp=TSA, form="Enveloping"),
        validate("v-altered", "Document changed after signing", ["V-30", "integrity"], "sample:tampered-content", {"outcome": "invalid", "indication": "TOTAL_FAILED"}),
        validate("v-cades-altered", "CAdES: data changed", ["V-30", "integrity"], "cades-sample:v-changed-data", {"outcome": "invalid"},
                 data_id="cades-sample:v-changed-data#data"),
        validate("v-xades-altered", "XAdES: document changed", ["V-30", "integrity"], "xades-sample:v-changed", {"outcome": "invalid"}),
        validate("viewer", "Validation report of a B-LTA signature", ["F-30", "V-30", "report"], "step:pades-blta", {"outcome": "valid"},
                 desc="The validation report shows integrity, signing time, public key and certificate data; the CLI writes it as HTML with "
                      "simplesign validate --html-report report.html --report-language es."),
    ]},
    {"id": "crypto", "title": "Algorithms", "steps": [
        sign("rsa-1024", "RSA 1024 key: refused", ["F-28", "V-28", "algorithms"], refused("KeyTooWeak"), credentialId="sandbox:rsa-1024"),
        *[sign(f"alg-{c}", f"Sign with {c.upper()}", ["F-28", "algorithms"], {"outcome": "signed"}, credentialId=f"sandbox:{c}")
          for c in ("rsa-4096", "ecdsa-p256", "ecdsa-p384")],
        sign("chain-sha1", "Chain with a CA signed with SHA-1: refused", ["F-28", "V-28", "algorithms"], refused("AlgorithmNotPermitted"), credentialId="sandbox:under-sha1-ca"),
        *[sign(f"rsa-1024-{f}", f"{f.upper()}: RSA 1024 key", ["F-28", "algorithms"], refused("KeyTooWeak"), fmt=f, credentialId="sandbox:rsa-1024")
          for f in ("cades", "xades")],
    ]},
    {"id": "audit", "title": "Audit log", "steps": [
        sign("audit", "Audit record of each signature", ["F-15", "V-15", "audit"], {"outcome": "signed", "logContains": ["Audit:"]},
             signingControls={"trust": ["SandboxRoot"], "auditLog": True},
             desc="Each signature made or refused is recorded (certificate, policy, input and output hashes, reason) in a hash-chained log; "
                  "the CLI checks it with simplesign audit verify."),
        sign("audit-refused", "A refused signature is recorded too", ["F-15", "V-15", "audit"], {"outcome": "refused", "reason": "CertificateRevoked", "logContains": ["Audit:"]},
             credentialId="sandbox:revoked", signingControls={"trust": ["SandboxRoot"], "auditLog": True}),
    ]},
]

playbook = {
    "$schema": "https://raw.githubusercontent.com/eupassarin/SimpleSign/main/docs/schemas/playbook.schema.json",
    "schema": 2,
    "id": "indecopi-guia-v4",
    "title": "INDECOPI software accreditation (Guide v4.0)",
    "description": "The automated part of an INDECOPI (IOFE, Peru) accreditation of signing and verification software (Guía de Acreditación "
                   "de Software v4.0, annex B): each step runs against the Sandbox with the IOFE policy, through the library and the CLI, "
                   "cross-validated with EU DSS when one is connected. "
                   "Tags name the items of the guide (F-n signing, V-n verification, S-n time-stamps) and a topic.",
    "defaults": {
        "engine": "both",
        "format": "pades",
        # Every file a step produces is also validated by EU DSS when one is connected; without DSS the steps still run.
        "crossValidate": True,
        "options": {
            "common": {"level": "BB", "credentialId": "sandbox:rsa-2048", "signingPolicyId": "preset:signing:iofe",
                       "signingControls": {"trust": ["SandboxRoot"]}, "attemptRefused": True,
                       "validation": {"trust": ["Sandbox"], "policyId": "preset:validation:iofe"}},
            "pades": {"documentId": "sample:contract"},
        },
    },
    "sections": sections,
}

out = sys.argv[1]
with open(out, "w", encoding="utf-8") as f:
    json.dump(playbook, f, ensure_ascii=False, indent=2)
    f.write("\n")
print(sum(len(s["steps"]) for s in sections), "steps")
