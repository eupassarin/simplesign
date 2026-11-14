"""Writes docs/playbooks/eidas-baseline.json: the eIDAS profile (SimpleSign.Europe.Eidas) run against the Sandbox's list of
trusted lists, read the eIDAS way, through the library and the CLI: the faults of the lists, the qualification of the
signatures (ETSI TS 119 615 and TS 119 172-4) and of the time-stamps.

Tags name the items of docs/playbooks/eidas-checklist.md (L-n: trusted lists; Q-n: qualification of the signature; T-n:
time-stamps) and a topic. The checklist maps each item to the steps that show it.

    python3 tools/playbooks/eidas.py docs/playbooks/eidas-baseline.json
"""
import json
import sys

from describe import describe

# The eidas profile on the Sandbox: its LOTL (/tl/lotl.xml) and the list it points to. The CLI says --profile eidas --sandbox URL.
EIDAS_ON_SANDBOX = {"profile": "Eidas", "profileSource": "Sandbox"}


def sign(id, title, tags, expect, desc=None, sandbox=None, **opts):
    s = {"id": id, "title": title, "tags": tags, "options": opts, "expect": expect}
    if desc:
        s["description"] = desc
    if sandbox:
        s["sandbox"] = sandbox
    return s


def validate(id, title, tags, file_id, expect, desc=None, sandbox=None, **settings):
    options = {"fileId": file_id, "settings": {"trust": [], **EIDAS_ON_SANDBOX, "policyId": "preset:validation:eidas", **settings}}
    s = {"id": id, "kind": "validate", "title": title, "tags": tags, "options": options, "expect": expect}
    if desc:
        s["description"] = desc
    if sandbox:
        s["sandbox"] = sandbox
    return s


def refused(reason):
    return {"outcome": "refused", "reason": reason}


def signed(qualification, **more):
    return {"outcome": "signed", "qualification": qualification, **more}


sections = [
    {"id": "lists", "title": "Trusted lists (LOTL and TL)",
     "description": "The anchors come from the Sandbox's LOTL and the list it points to, each checked against the certificate of its operator "
                    "(the LOTL's, then the one the LOTL names). A list that is expired, signed by another key or changed gives no anchors: "
                    "signing is refused, validation finds no chain. For validation an expired national list is kept and the eidas policy's "
                    "TLNotExpired (FAIL) judges it; an expired LOTL is always refused.",
     "steps": [
         sign("tl-ok", "Sign with a qualified certificate the Sandbox's lists vouch for", ["L-1", "L-2", "Q-1", "lists"], signed("QESig"),
              desc="The LOTL is checked with its operator's certificate, the TL with the one the LOTL names; the signer chains to the CA/QC service."),
         sign("tl-wrong-signer", "TL signed by another key: refused", ["L-2", "lists"], refused("UntrustedRoot"), sandbox={"trustedList": "WrongSigner"}),
         sign("tl-tampered", "TL changed after signing: refused", ["L-2", "lists"], refused("UntrustedRoot"), sandbox={"trustedList": "Tampered"}),
         sign("tl-expired", "Expired TL: refused for signing", ["L-3", "lists"], refused("UntrustedRoot"), sandbox={"trustedList": "Expired"}),
         sign("lotl-wrong-signer", "LOTL signed by another key: refused", ["L-1", "lists"], refused("UntrustedRoot"), sandbox={"lotl": "WrongSigner"}),
         sign("lotl-tampered", "LOTL changed after signing: refused", ["L-1", "lists"], refused("UntrustedRoot"), sandbox={"lotl": "Tampered"}),
         sign("lotl-expired", "Expired LOTL: refused", ["L-3", "lists"], refused("UntrustedRoot"), sandbox={"lotl": "Expired"}),
         validate("v-tl-ok", "Validate under the eidas profile", ["L-1", "L-2", "Q-1", "lists"], "step:tl-ok",
                  {"outcome": "valid", "indication": "TOTAL_PASSED", "qualification": "QESig"}),
         validate("v-tl-wrong-signer", "Validate with a fake TL: no chain, not under eIDAS", ["L-2", "lists"], "step:tl-ok",
                  {"outcome": "indeterminate", "subIndication": "NO_CERTIFICATE_CHAIN_FOUND", "qualification": "N/A"},
                  sandbox={"trustedList": "WrongSigner"}),
         validate("v-tl-expired", "Validate with an expired TL: TLNotExpired fails", ["L-3", "lists"], "step:tl-ok",
                  {"outcome": "indeterminate", "subIndication": "TRY_LATER", "qualification": "Indeterminate QESig"},
                  sandbox={"trustedList": "Expired"}),
         validate("v-lotl-wrong-signer", "Validate with a fake LOTL: no chain", ["L-1", "lists"], "step:tl-ok",
                  {"outcome": "indeterminate", "subIndication": "NO_CERTIFICATE_CHAIN_FOUND"}, sandbox={"lotl": "WrongSigner"}),
     ]},
    {"id": "qualification", "title": "Qualification of the signature (TS 119 615, TS 119 172-4)",
     "description": "The CA/QC service of the Sandbox's TL, its Qualifications extension and the QC statements of each signer give the "
                    "qualification of the signature: QESig and QESeal (qualified, key on a QSCD), AdESig-QC (qualified, no QSCD), AdESig "
                    "(not qualified, or under a CA/PKC service).",
     "steps": [
         sign("q-adesig-qc", "Qualified certificate without a QSCD", ["Q-1", "Q-3", "qualification"], signed("AdESig-QC"), credentialId="sandbox:qc-esign"),
         sign("q-qeseal", "Qualified seal certificate on a QSCD", ["Q-1", "Q-4", "qualification"], signed("QESeal"), credentialId="sandbox:qc-eseal-qscd"),
         sign("q-qscd-by-list", "QSCD declared by the trusted list (QCWithQSCD)", ["Q-2", "Q-3", "qualification"], signed("QESig"),
              credentialId="sandbox:qc-esign-policy",
              desc="The certificate has no QcSSCD, but its policy is QCP-n-qscd and the TL's Qualifications extension says QCWithQSCD for it."),
         sign("q-not-qualified", "Certificate without QC statements", ["Q-1", "qualification"], signed("AdESig"), credentialId="sandbox:rsa-2048"),
         sign("q-under-pkc", "QC statements under a CA/PKC service", ["Q-5", "qualification"], signed("AdESig"), credentialId="sandbox:pkc-esign",
              desc="The certificate claims QcCompliance and QcSSCD, but its CA is listed as CA/PKC: the list does not vouch for it as qualified."),
         sign("q-policy-refuses", "A policy that asks for a qualified certificate on a QSCD refuses a non-qualified one", ["Q-6", "qualification"],
              refused("CertificateNotQualified"), credentialId="sandbox:rsa-2048", signingPolicyId="playbook:eidas-qualified"),
         sign("q-policy-accepts", "The same policy signs with a qualified certificate on a QSCD", ["Q-6", "qualification"], signed("QESig"),
              signingPolicyId="playbook:eidas-qualified"),
     ]},
    {"id": "timestamps", "title": "Time-stamps (TSA/QTST)",
     "description": "A time-stamp is a qualified electronic time-stamp when a TSA/QTST service of the lists, granted at its time, issued it. "
                    "The eidas signing policy refuses a TSA that is not trusted or whose certificate is revoked.",
     "steps": [
         sign("ts-qualified", "B-T with the qualified TSA", ["T-1", "Q-1", "timestamps"], signed("QESig", level="B-T", timestampQualification="QTSA"),
              level="BT", timestamp={"provider": "Sandbox"}),
         sign("ts-non-qualified", "B-T with a non-qualified TSA (a TSA service)", ["T-2", "timestamps"], signed("QESig", level="B-T", timestampQualification="TSA"),
              level="BT", timestamp={"provider": "SandboxNonQualified"}),
         sign("ts-revoked", "B-T with the withdrawn TSA, whose certificate is revoked: refused", ["T-3", "timestamps"], refused("TimestampCertificateRevoked"),
              level="BT", timestamp={"provider": "SandboxRevoked"}),
         sign("ts-untrusted", "B-T with a TSA outside the lists: refused", ["T-3", "timestamps"], refused("TimestampUntrusted"),
              level="BT", timestamp={"provider": "SandboxUntrusted"}),
         validate("v-withdrawn-after-use", "CA/QC withdrawn after the signature: still qualified by its history", ["L-4", "Q-1", "T-1", "timestamps"],
                  "step:ts-qualified", {"outcome": "valid", "qualification": "QESig", "timestampQualification": "QTSA"},
                  sandbox={"trustedList": "WithdrawnAfterUse"},
                  desc="The time-stamp proves the signature existed while the root's CA/QC service was granted (its ServiceHistory)."),
     ]},
]

# Signing only with a qualified certificate whose key is on a QSCD: the eidas policy, with the QC checks failing.
QUALIFIED = [
    {"id": "eidas-qualified", "kind": "signing", "base": "eidas",
     "set": {"SigningCertificate/QcCompliance": {"Level": "FAIL"}, "SigningCertificate/QcSSCD": {"Level": "FAIL"}}},
]

EIDAS = {"trust": [], **EIDAS_ON_SANDBOX}


# What each step runs and why, for the steps above that give no desc (describe.py puts them in place).
DESCRIPTIONS = {
    "tl-wrong-signer":
        "The national TL is signed by a key other than the one the LOTL names for its operator: it must not be used, so "
        "there are no anchors and the eidas policy refuses to sign (UntrustedRoot).",
    "tl-tampered":
        "The TL's content changed after it was signed, so its XML signature breaks: no anchors, signing refused.",
    "tl-expired":
        "The TL is past its NextUpdate: for signing an outdated list gives no anchors, so the signature is refused.",
    "lotl-wrong-signer":
        "The LOTL is signed by a key other than its operator's: nothing it points to can be trusted, so signing is "
        "refused.",
    "lotl-tampered":
        "The LOTL changed after it was signed: its signature breaks, nothing is trusted, signing refused.",
    "lotl-expired":
        "The LOTL is past its NextUpdate: an expired LOTL is always refused, so there are no anchors and signing is "
        "refused.",
    "v-tl-ok":
        "Validates the tl-ok file under the eidas profile and policy with good lists: TOTAL_PASSED and qualified as "
        "QESig (qualified certificate, key on a QSCD).",
    "v-tl-wrong-signer":
        "Validates the same file while the TL has another signer: no anchors, so NO_CERTIFICATE_CHAIN_FOUND, and the "
        "qualification is N/A because the signature is not under eIDAS at all.",
    "v-tl-expired":
        "Validates it while the TL has expired: for validation the list is kept but the policy's TLNotExpired fails, so "
        "the result is INDETERMINATE / TRY_LATER and the qualification 'Indeterminate QESig' (it would be QESig with a "
        "current list).",
    "v-lotl-wrong-signer":
        "Validates it while the LOTL has another signer: nothing is trusted, NO_CERTIFICATE_CHAIN_FOUND.",
    "q-adesig-qc":
        "Signs with a qualified certificate (QcCompliance) whose key is not on a QSCD: an advanced signature supported "
        "by a qualified certificate, AdESig-QC, not QESig.",
    "q-qeseal":
        "Signs with a qualified certificate for electronic seals (QcType eseal) on a QSCD: QESeal, the seal counterpart "
        "of QESig.",
    "q-not-qualified":
        "Signs with a certificate that has no QC statements: an advanced electronic signature only (AdESig).",
    "q-policy-refuses":
        "Signs with the non-qualified certificate under a policy that sets QcCompliance and QcSSCD to FAIL: a service "
        "that must make qualified signatures refuses it (CertificateNotQualified).",
    "q-policy-accepts":
        "The same policy with the default qualified certificate on a QSCD: the signature is made and qualified as "
        "QESig.",
    "ts-qualified":
        "Signs at B-T with the Sandbox's main TSA, listed as a TSA/QTST service: the signature is QESig and its "
        "time-stamp a qualified electronic time-stamp (QTSA).",
    "ts-non-qualified":
        "Signs at B-T with a TSA listed only as a TSA service: the signature is still QESig, but its time-stamp is not "
        "qualified (TSA).",
    "ts-revoked":
        "Signs at B-T with the withdrawn TSA, whose certificate is revoked: the eidas signing policy refuses its token "
        "(TimestampCertificateRevoked).",
    "ts-untrusted":
        "Signs at B-T with a TSA that is in none of the lists: its token is not trusted, refused (TimestampUntrusted).",
}

sections = describe(sections, DESCRIPTIONS)

playbook = {
    "$schema": "https://raw.githubusercontent.com/eupassarin/SimpleSign/main/docs/schemas/playbook.schema.json",
    "schema": 2,
    "id": "eidas-baseline",
    "title": "eIDAS: trusted lists and qualification",
    "description": "The eIDAS profile (SimpleSign.Europe.Eidas) against the Sandbox's list of trusted lists, through the library and the CLI: "
                   "the faults of the LOTL and the TL, the qualification of each signature (QESig, QESeal, AdESig-QC, AdESig) and of its "
                   "time-stamps (QTSA). Tags name the items of docs/playbooks/eidas-checklist.md. Not cross-validated with EU DSS: the "
                   "TestBench does not compare DSS's qualification yet.",
    "defaults": {
        "engine": "both",
        "format": "pades",
        "crossValidate": False,
        "options": {
            "common": {"level": "BB", "credentialId": "sandbox:qc-esign-qscd", "signingPolicyId": "preset:signing:eidas",
                       "signingControls": EIDAS, "attemptRefused": True,
                       "validation": {**EIDAS, "policyId": "preset:validation:eidas"}},
            "pades": {"documentId": "sample:contract"},
        },
    },
    "policies": QUALIFIED,
    "sections": sections,
}

out = sys.argv[1]
with open(out, "w", encoding="utf-8") as f:
    json.dump(playbook, f, ensure_ascii=False, indent=2)
    f.write("\n")
print(sum(len(s["steps"]) for s in sections), "steps")
