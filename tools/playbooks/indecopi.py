"""Writes docs/playbooks/indecopi-guia-v4.json: the automated steps that help with an INDECOPI (IOFE, Peru) software
accreditation (Guía de Acreditación de Aplicaciones de Software v4.0, annex B), run in the TestBench against the Sandbox.

Tags name the annex B items each step helps with (F-n: section 4.2, signing by an automated agent; V-n: section 4.3,
verification by automated agents; S-n: section 4.4, time-stamps) and a topic. Items that need a person (manuals, code
signing, the cryptographic module) are not here: docs/playbooks/indecopi-checklist.md says where each one is handled.

    python3 tools/playbooks/indecopi.py docs/playbooks/indecopi-guia-v4.json
"""
import json
import sys

from describe import describe

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


# The iofe profile reading the Sandbox's list (/tl/tl.xml) instead of INDECOPI's: the CLI says --profile iofe --sandbox URL.
IOFE_ON_SANDBOX = {"profile": "Iofe", "profileSource": "Sandbox"}
TSL = {"trust": [], **IOFE_ON_SANDBOX}
IOFE_VALIDATION = {"trust": [], **IOFE_ON_SANDBOX}

sections = [
    {"id": "tsl", "title": "Trusted list (TSL)",
     "description": "The iofe profile on the Sandbox: the trust anchors come from the Sandbox's trusted list (/tl/tl.xml), read as IofeExtension reads INDECOPI's "
                    "(IofeExtension.DefaultListOptions: the CA services and the services typed 'unspecified', as INDECOPI types its TSAs "
                    "and signature software, never a code-signing certificate); its signature is checked against the operator's certificate.",
     "steps": [
         sign("tsl-ok", "Sign with a root listed in the TSL", ["F-1", "F-3", "tsl"], {"outcome": "signed"}, signingControls=TSL,
              desc="The Sandbox's TSL is downloaded, its signature is checked with the operator's certificate, and the signer's root is listed: the signature is made."),
         sign("tsl-wrong-signer", "TSL signed by another key: refused", ["F-1", "tsl"], refused("UntrustedRoot"), sandbox={"trustedList": "WrongSigner"}, signingControls=TSL,
              desc="The Sandbox publishes a TSL signed by a key that is not the operator's (a fake TSL): there are no anchors and the signature is refused."),
         sign("tsl-tampered", "Tampered TSL: refused", ["F-1", "tsl"], refused("UntrustedRoot"), sandbox={"trustedList": "Tampered"}, signingControls=TSL),
         sign("tsl-expired", "Expired TSL: refused", ["F-2", "tsl"], refused("UntrustedRoot"), sandbox={"trustedList": "Expired"}, signingControls=TSL,
              desc="The published TSL has its NextUpdate in the past."),
         {**sign("tsl-tsa-unspecified", "Time-stamp from a TSA whose CA the TSL lists as 'unspecified'", ["S-1", "F-3", "tsl", "tsa"],
                 {"outcome": "signed", "level": "B-T"}, level="BT", timestamp={"provider": "SandboxIofe"}, signingControls=TSL,
                 validation=IOFE_VALIDATION,
                 desc="As INDECOPI lists the Llama.pe Timestamping CA (not its TSU) with the service type 'unspecified', the TSL names the "
                      "self-signed CA of the Sandbox's IOFE TSA: its time-stamp chains to that service and the signature is made. "
                      "Not cross-validated: DSS trusts every granted service of the list whatever its type, so it does not show the "
                      "'unspecified' rule this step is about."),
            "crossValidate": False},
         {**sign("tsl-tsa-unlisted", "Same TSA without the TSL: refused", ["S-1", "tsl", "tsa"], refused("TimestampUntrusted"), level="BT",
                 timestamp={"provider": "SandboxIofe"},
                 desc="With the Sandbox root as the only anchor, the IOFE TSA chains to nothing trusted: the 'unspecified' service of the "
                      "TSL is what makes it trusted in tsl-tsa-unspecified."),
            "crossValidate": False},
         validate("v-tsl-ok", "Validate with anchors from the TSL", ["V-1", "V-3", "tsl"], "step:tsl-ok", {"outcome": "valid"}, trust=[], **IOFE_ON_SANDBOX),
         # A list whose signature fails is not used: no anchor. An expired one is used, and IOFE's TLNotExpired (FAIL) judges it.
         validate("v-tsl-wrong-signer", "Validate with a fake TSL", ["V-1", "tsl"], "step:tsl-ok", {"outcome": "indeterminate", "subIndication": "NO_CERTIFICATE_CHAIN_FOUND"},
                  sandbox={"trustedList": "WrongSigner"}, trust=[], **IOFE_ON_SANDBOX),
         validate("v-tsl-expired", "Validate with an expired TSL", ["V-2", "tsl"], "step:tsl-ok", {"outcome": "indeterminate", "subIndication": "TRY_LATER"},
                  sandbox={"trustedList": "Expired"}, trust=[], **IOFE_ON_SANDBOX),
         validate("v-tsl-tsa-unspecified", "Validate a time-stamp whose TSA's CA the TSL lists as 'unspecified'", ["V-3", "S-1", "tsl", "tsa"],
                  "step:tsl-tsa-unspecified", {"outcome": "valid"}, trust=[], **IOFE_ON_SANDBOX),
     ]},
    {"id": "agent", "title": "Key usage of an automated agent",
     "description": "Section 4.2 asks an automated agent to check the nonRepudiation bit, and section 4.3 the software verifying what agents "
                    "receive: the iofe policies with KeyUsage = nonRepudiation (declared in policies). The other certificate checks (validity, "
                    "a key usage not meant for signing, revocation) are the same under any policy: sandbox-basics shows them.",
     "steps": [
        sign("signed-no-nonrepudiation", "Sign with a certificate without nonRepudiation (to validate)", ["F-12", "key-usage"], {"outcome": "signed"},
             credentialId="sandbox:no-nonrepudiation",
             desc="The iofe signing policy accepts digitalSignature or nonRepudiation (as section 4.1 does for end-user software); "
                  "the file is used by the validation step that requires nonRepudiation."),
        sign("no-nonrepudiation-agent", "Automated agent: a certificate without nonRepudiation is refused", ["F-12", "key-usage"],
             refused("KeyUsageNotPermitted"), credentialId="sandbox:no-nonrepudiation", signingPolicyId="playbook:iofe-agent",
             desc="Section 4.2 (annex B item 12) asks an automated agent to check the nonRepudiation bit: the iofe policy with "
                  "KeyUsage = nonRepudiation (playbook:iofe-agent) refuses a certificate that has digitalSignature only."),
        sign("key-usage-file", "Signer with neither digitalSignature nor nonRepudiation (minimal signing policy, to validate)", ["V-12", "key-usage"],
             {"outcome": "signed"}, credentialId="sandbox:no-signing-key-usage", signingPolicyId="preset:signing:minimal", validate=False,
             desc="Signs with a certificate whose key usage allows neither digitalSignature nor nonRepudiation, under the minimal signing "
                  "policy and without validating, only to produce the file v-key-usage validates."),
        validate("v-key-usage", "IOFE validation: a signer with neither digitalSignature nor nonRepudiation is not accepted", ["V-12", "key-usage"],
                 "step:key-usage-file", {"outcome": "indeterminate"},
                 desc="The IOFE validation policy requires digitalSignature or nonRepudiation in the signing certificate (Req. 23), where the "
                      "library's default only warns: the certificate without either fails the constraint (INDETERMINATE)."),
        validate("v-no-nonrepudiation", "Validation requires nonRepudiation: not accepted", ["V-12", "key-usage"], "step:signed-no-nonrepudiation",
                 {"outcome": "indeterminate"}, policyId="playbook:iofe-agent-validation",
                 desc="With the iofe policy requiring nonRepudiation (playbook:iofe-agent-validation) the certificate without it fails "
                      "the chain constraint (EN 319 102-1: INDETERMINATE)."),
    ]},
    {"id": "report", "title": "Validation report",
     "description": "What the guide asks a viewer to show the signer and the relying parties (F-30, V-30), in Spanish.",
     "steps": [
        validate("viewer", "Validation report of a signature trusted through the TSL", ["F-30", "V-30", "report"], "step:tsl-ok", {"outcome": "valid"},
                 trust=[], **IOFE_ON_SANDBOX,
                 desc="Validates the tsl-ok file as INDECOPI's relying parties would (anchors from the TSL, IOFE policy): the report shows "
                      "integrity, signing time, public key and certificate data; the CLI writes it as HTML with "
                      "simplesign validate --html-report report.html --report-language es."),
    ]},
    {"id": "audit", "title": "Audit log",
     "description": "The audit trail the guide asks of signing software (F-15, V-15): every attempt, made or refused, leaves a record.",
     "steps": [
        sign("audit", "Audit record of each signature", ["F-15", "V-15", "audit"], {"outcome": "signed", "logContains": ["Audit:"]},
             signingControls={"trust": ["SandboxRoot"], "auditLog": True},
             desc="Each signature made or refused is recorded (certificate, policy, input and output hashes, reason) in a hash-chained log; "
                  "the CLI checks it with simplesign audit verify."),
        sign("audit-refused", "A refused signature is recorded too", ["F-15", "V-15", "audit"], {"outcome": "refused", "reason": "CertificateRevoked", "logContains": ["Audit:"]},
             credentialId="sandbox:revoked", signingControls={"trust": ["SandboxRoot"], "auditLog": True}),
    ]},
]


# What each step runs and why, for the steps above that give no desc (describe.py puts them in place).
DESCRIPTIONS = {
    "tsl-tampered":
        "The Sandbox publishes a TSL whose content changed after it was signed, so its XML signature breaks: it must not "
        "be used, there are no anchors, and signing is refused (UntrustedRoot).",
    "v-tsl-ok":
        "Validates the tsl-ok file with the anchors read from the TSL and the IOFE validation policy: valid.",
    "v-tsl-wrong-signer":
        "Validates the same file while the TSL is signed by another key: the fake list gives no anchors, so "
        "NO_CERTIFICATE_CHAIN_FOUND.",
    "v-tsl-expired":
        "Validates it while the TSL is past its NextUpdate: the IOFE policy's TLNotExpired fails, so the validator asks "
        "to try later (INDETERMINATE / TRY_LATER) instead of accepting.",
    "v-tsl-tsa-unspecified":
        "Validates the B-T file whose TSA chains to a CA the TSL lists as 'unspecified': the time-stamp is trusted "
        "through the list, so the signature is valid.",
    "audit-refused":
        "A refused signature (a revoked certificate) with the audit log on: the attempt must be recorded too, with its "
        "refusal, not only the signatures made.",
}

sections = describe(sections, DESCRIPTIONS)

# What section 4.2 (annex B item 12) asks of an automated agent, and section 4.3 (Req. 23) of the software verifying what
# agents receive: the iofe policy with the nonRepudiation bit required.
NON_REPUDIATION = {"Level": "FAIL", "Id": ["nonRepudiation"]}
AGENT_POLICIES = [
    {"id": "iofe-agent", "kind": "signing", "base": "iofe", "set": {"SigningCertificate/KeyUsage": NON_REPUDIATION}},
    {"id": "iofe-agent-validation", "kind": "validation", "base": "iofe",
     "set": {"SignatureConstraints/BasicSignatureConstraints/SigningCertificate/KeyUsage": NON_REPUDIATION}},
]

playbook = {
    "$schema": "https://raw.githubusercontent.com/eupassarin/SimpleSign/main/docs/schemas/playbook.schema.json",
    "schema": 2,
    "id": "indecopi-guia-v4",
    "title": "INDECOPI software accreditation (Guide v4.0)",
    "description": "The automated part of an INDECOPI (IOFE, Peru) accreditation of signing and verification software (Guía de Acreditación "
                   "de Software v4.0, annex B): each step runs against the Sandbox with the IOFE policy, through the library and the CLI, "
                   "cross-validated with EU DSS when one is connected. "
                   "Tags name the items of annex B of the guide (F-n: section 4.2, signing by an automated agent; V-n: section 4.3, "
                   "verification by automated agents; S-n: section 4.4, time-stamps) and a topic; docs/playbooks/indecopi-checklist.md "
                   "maps every item to a step, a test or what is left to the accredited product. "
                   "It complements sandbox-basics and etsi-baseline: the checks any signer or validator makes whatever the policy "
                   "(revocation, validity, time-stamps, levels, algorithms, changed files) are shown there, and the checklist names "
                   "those steps; here are only the ones the IOFE profile and policies decide (the TSL, nonRepudiation for an "
                   "automated agent), the report and the audit trail.",
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
    "policies": AGENT_POLICIES,
    "sections": sections,
}

out = sys.argv[1]
with open(out, "w", encoding="utf-8") as f:
    json.dump(playbook, f, ensure_ascii=False, indent=2)
    f.write("\n")
print(sum(len(s["steps"]) for s in sections), "steps")
