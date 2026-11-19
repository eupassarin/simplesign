#!/usr/bin/env python3
"""The accreditation audit, run: INDECOPI's guide v4.0, annex B, shown by the accredited configuration itself.

Every scenario prepares a running SimpleSign Sandbox through its API (a failure of the CRL, OCSP, TSA or trusted
list, a revocation, a credential), runs `simplesign iofe sign|verify|view` — the commands of
SimpleSign.Peru.Iofe.Accredited, not the general signers — and checks what came out: the signature, or the refusal
and its reason. What it ran, what it printed, the audit records and the files are kept as evidence, with a report
in English and Spanish.

    python3 auditoria.py                       every scenario, key in the Sandbox's remote signing service
    python3 auditoria.py --key both            also with the key in a PKCS#11 token (SoftHSM2)
    python3 auditoria.py --item F-8            the scenarios of one item of annex B, shown step by step
    python3 auditoria.py --scenario revocado   one scenario
    python3 auditoria.py --list                what there is to run
    python3 auditoria.py --write-catalog       writes escenarios.json (checked against the checklist by the tests)

Needs: Python 3.9+, a running Sandbox (--sandbox, default http://localhost:5300), and `simplesign` with the IOFE
extension installed (--cli, default "simplesign"). For --key pkcs11: a token filled by
tools/stack/softhsm-provision.sh and SOFTHSM2_CONF pointing to it.

The Sandbox is a test PKI: nothing there proves what only the real environment can (the HSM's certification, the
provider's accreditation, INDECOPI's own list). The same scenarios run in a real one, described by a file:

    python3 auditoria.py --entorno entorno.json --list      what this environment can show, and why not the rest
    python3 auditoria.py --entorno entorno.json             runs it: the operator's HSM, INDECOPI's list, the real CA
    python3 auditoria.py --entorno entorno.json --ensayo evidencias-ensayo
                                                            and points, for what it cannot show, to a Sandbox run

There no Sandbox is asked for and nothing of it is used; entorno.ejemplo.json describes the file. A scenario the
environment cannot show (a CRL signed with another key, a revoked TSA, a certificate nobody issued) is reported as
not run there, with the reason. These are real signatures, made with the organization's key: the documents are the
script's test documents and every one is in the run's own audit trail. docs/audit-walkthrough.md has the steps.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import datetime
import hashlib
import html
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
CATALOG = HERE / "escenarios.json"
LANGS = ("en", "es")

# What the Sandbox publishes about itself; a real deployment declares its own module or service.
MODULE = {"manufacturer": "SoftHSM project", "model": "SoftHSM v2",
          "certification": "ninguna (token de software para pruebas)", "certificate": "n/a"}
SERVICE = {"provider": "SimpleSign Sandbox", "accreditation": "ninguna (servicio de pruebas)", "reference": "n/a"}
TOKEN_LABEL = "SimpleSign Sandbox"
SENDER = "20123456789"
INDECOPI_LIST = "https://iofe.indecopi.gob.pe/TSL/tsl-pe.xml"
# The role scenarios ask the organization's own signing certificate by, and its other name in an environment file.
SIGNER, DEFAULT = "rsa-2048", "default"
# A declaration no module answers to.
OTHER_MODULE = {"manufacturer": "Fabricante no declarado", "model": "Modelo no declarado"}

TEXT = {
    "title": {"en": "Accreditation audit — INDECOPI guide v4.0, annex B",
              "es": "Auditoría de acreditación — Guía INDECOPI v4.0, Anexo B"},
    "intro": {"en": "Every scenario was run by the accredited configuration (`simplesign iofe`, package "
                    "SimpleSign.Peru.Iofe.Accredited) against a SimpleSign Sandbox, a test PKI. The documents the "
                    "verification agent receives were prepared with test tools: the agent is what judges them.",
              "es": "Cada escenario fue ejecutado por la configuración acreditada (`simplesign iofe`, paquete "
                    "SimpleSign.Peru.Iofe.Accredited) contra un SimpleSign Sandbox, una PKI de pruebas. Los "
                    "documentos que el agente de verificación recibe se prepararon con herramientas de prueba: "
                    "quien los juzga es el agente."},
    "intro_real": {"en": "Every scenario was run by the accredited configuration (`simplesign iofe`, package "
                         "SimpleSign.Peru.Iofe.Accredited) in the environment described below: the keys in the "
                         "operator's cryptographic module, the certificates of a real CA and its revocation "
                         "services. A scenario this environment cannot show is reported as not run, with the "
                         "reason.",
                   "es": "Cada escenario fue ejecutado por la configuración acreditada (`simplesign iofe`, paquete "
                         "SimpleSign.Peru.Iofe.Accredited) en el entorno descrito abajo: las claves en el módulo "
                         "criptográfico del operador, los certificados de una EC real y sus servicios de "
                         "revocación. Un escenario que este entorno no permite mostrar figura como no ejecutado, "
                         "con el motivo."},
    "intro_rehearsal": {"en": "For those scenarios the result of the rehearsal in a SimpleSign Sandbox (a test "
                              "PKI) is given; it is not evidence of this environment.",
                        "es": "Para esos escenarios se indica el resultado del ensayo en un SimpleSign Sandbox "
                              "(una PKI de pruebas), que no es evidencia de este entorno."},
    "passed": {"en": "PASSED", "es": "CONFORME"},
    "failed": {"en": "FAILED", "es": "NO CONFORME"},
    "skipped": {"en": "SKIPPED", "es": "OMITIDO"},
    "not_here": {"en": "NOT RUN IN THIS ENVIRONMENT", "es": "NO EJECUTADO EN ESTE ENTORNO"},
    "runs": {"en": "runs", "es": "se ejecuta"},
    "rehearsal": {"en": "rehearsal in the Sandbox", "es": "ensayo en el Sandbox"},
    "setup": {"en": "Set-up", "es": "Preparación"},
    "environment_files": {"en": "Environment data and certificate profiles",
                          "es": "Datos del entorno y perfil de los certificados"},
    "na_fault": {"en": "needs a failure of a third party (only the Sandbox makes one)",
                 "es": "requiere provocar una falla de un tercero (solo en el Sandbox)"},
    "na_key": {"en": "the environment has no key with a certificate for",
               "es": "el entorno no tiene clave con certificado para"},
    "na_received": {"en": "the environment has no received document for",
                    "es": "el entorno no tiene documento recibido para"},
    "na_tsa": {"en": "the environment declares no time-stamp authority (tsa)",
               "es": "el entorno no declara autoridad de sellado de tiempo (tsa)"},
    "na_other_root": {"en": "the environment gives no unrelated root certificate (otherRoot)",
                      "es": "el entorno no da un certificado raíz ajeno (otherRoot)"},
    "na_list_copy": {"en": "the environment gives no copy of the trusted list for",
                     "es": "el entorno no da una copia de la lista de confianza para"},
    "na_roots": {"en": "the environment trusts installed roots, not a trusted list",
                 "es": "el entorno confía en raíces instaladas, no en una lista de confianza"},
    "na_remote": {"en": "the environment has no remote signing service",
                  "es": "el entorno no tiene servicio de firma remota"},
    "na_allow": {"en": "it acts on the module (a wrong PIN counts towards locking it): enabled in allow",
                 "es": "tiene efecto sobre el módulo (un PIN incorrecto cuenta para su bloqueo): se habilita en "
                       "allow"},
    "summary": {"en": "Summary", "es": "Resumen"},
    "by_item": {"en": "By item of annex B", "es": "Por ítem del Anexo B"},
    "scenarios": {"en": "Scenarios", "es": "Escenarios"},
    "item": {"en": "Item", "es": "Ítem"},
    "asks": {"en": "What the guide asks", "es": "Lo que pide la Guía"},
    "scenario": {"en": "Scenario", "es": "Escenario"},
    "key": {"en": "Key", "es": "Clave"},
    "result": {"en": "Result", "es": "Resultado"},
    "expected": {"en": "Expected", "es": "Esperado"},
    "found": {"en": "Found", "es": "Obtenido"},
    "command": {"en": "Command", "es": "Comando"},
    "output": {"en": "Output", "es": "Salida"},
    "sandbox": {"en": "Sandbox set-up", "es": "Preparación del Sandbox"},
    "evidence": {"en": "Evidence", "es": "Evidencia"},
    "no_scenario": {"en": "no scenario: see the checklist", "es": "sin escenario: ver la lista de verificación"},
    "environment": {"en": "Environment", "es": "Entorno"},
    "generated": {"en": "Generated", "es": "Generado"},
    "key_remote": {"en": "remote signing service", "es": "servicio de firma remota"},
    "key_pkcs11": {"en": "PKCS#11 module", "es": "módulo PKCS#11"},
    "key_none": {"en": "—", "es": "—"},
    "no_token": {"en": "no PKCS#11 token (SOFTHSM2_CONF and tools/stack/softhsm-provision.sh)",
                 "es": "sin token PKCS#11 (SOFTHSM2_CONF y tools/stack/softhsm-provision.sh)"},
    "exp_signed": {"en": "the signature is made", "es": "la firma se realiza"},
    "exp_refused": {"en": "it is refused and nothing is signed", "es": "se rechaza y nada se firma"},
    "exp_accepted": {"en": "the document is accepted", "es": "el documento se acepta"},
    "exp_rejected": {"en": "the document is rejected, with a notice to its sender",
                     "es": "el documento se rechaza, con comunicado al emisor"},
    "exp_fails": {"en": "the command fails", "es": "el comando falla"},
    "exp_ok": {"en": "the command succeeds", "es": "el comando termina bien"},
    "exp_text": {"en": "the output has", "es": "la salida contiene"},
    "exp_no_file": {"en": "no file is written", "es": "no se escribe el archivo"},
    "exp_file": {"en": "the file is written", "es": "se escribe el archivo"},
    "exp_audit": {"en": "the audit record", "es": "el registro de auditoría"},
    "exp_signer": {"en": "the output names the signer", "es": "la salida nombra al firmante"},
    "yes": {"en": "yes", "es": "sí"},
    "no": {"en": "no", "es": "no"},
}

# What annex B asks, by the number of the item in sections 4.2 (F) and 4.3 (V), which repeat each other, and 4.4 (S).
ITEMS = {
    "1": ("Trusted list (TSL): check the AAC's signature and that it chains to its root",
          "Lista de confianza (TSL): verificar la firma de la AAC y que corresponde a su raíz"),
    "2": ("TSL: check that it has not expired", "TSL: verificar que su vigencia no ha expirado"),
    "3": ("TSL: the certificate's root CA is listed", "TSL: la EC raíz del certificado figura en la lista"),
    "4": ("TSL: downloaded again according to its validity", "TSL: descarga periódica conforme a su vigencia"),
    "5": ("CRL fetched over HTTP, LDAP or HTTPS", "Consulta de CRL por HTTP, LDAP o HTTPS"),
    "6": ("The CRL is signed by the CA entitled to issue it", "La CRL está firmada por la EC autorizada"),
    "7": ("The CRL is current", "La CRL está vigente"),
    "8": ("The CRL is checked before signing: a revoked certificate never signs",
          "La CRL se verifica antes de firmar: un certificado revocado no firma"),
    "9": ("No certificate of the chain is revoked", "Ningún certificado de la cadena está revocado"),
    "10": ("Or OCSP (RFC 2560) for the certificate and its chain",
           "O consulta OCSP (RFC 2560) del certificado y su cadena"),
    "11": ("The certificate and its chain have not expired", "El certificado y su cadena no han expirado"),
    "12": ("The certificate's nonRepudiation bit is checked", "Se verifica el bit nonRepudiation del certificado"),
    "13": ("Protection against unauthorized access", "Protección contra accesos no autorizados"),
    "14": ("The checks cannot be switched off (except under a contingency INDECOPI approved)",
           "Las verificaciones no pueden desactivarse (salvo contingencia aprobada por el INDECOPI)"),
    "15": ("Audit log of the signatures, by kind of transaction",
           "Registros de auditoría de las firmas, por tipo de transacción"),
    "16": ("No signatures outside the defined transaction", "Sin firmas fuera de la transacción definida"),
    "17": ("The private key works only inside the certified cryptographic module",
           "La clave privada opera solo dentro del módulo criptográfico certificado"),
    "18": ("No automatic copies of the private key", "Sin copias automáticas de la clave privada"),
    "19": ("The solution's cryptographic module is FIPS 140-2 or Common Criteria EAL 4+",
           "El módulo criptográfico de la solución es FIPS 140-2 o Common Criteria EAL 4+"),
    "28": ("Current, unbroken algorithms", "Algoritmos vigentes, no obsoletos"),
    "29": ("The application is signed with a code-signing certificate",
           "La aplicación está firmada con un certificado de firma de código"),
    "30": ("Viewer: integrity, signing time, public key and certificate data",
           "Visor: integridad, fecha y hora, clave pública y datos del certificado"),
    "31": ("Signing time and the chain's public keys, attached and signed (validation data)",
           "Fecha y hora y claves públicas de la cadena, adjuntas y firmadas (datos de validación)"),
    "32": ("Administrator and user manuals", "Manuales de administración y de usuario"),
    "S-1": ("The token carries the identifier of the certificate of the TSA asked",
            "El sello lleva el identificador del certificado de la TSA consultada"),
    "S-2": ("The token's signature verifies", "La firma del sello de tiempo verifica"),
    "S-3": ("The TSA's certificate is not revoked", "El certificado de la TSA no está revocado"),
    "S-4": ("The TSA's certificate has not expired", "El certificado de la TSA no ha expirado"),
}


def item_text(item: str, lang: str) -> str:
    """What the guide asks in an item (F-8, V-8, S-1), in a language."""
    key = item if item.startswith("S-") else item.split("-", 1)[1]
    texts = ITEMS.get(key)
    return texts[LANGS.index(lang)] if texts else ""


def tr(key: str, lang: str) -> str:
    return TEXT[key][lang]


# ── Scenarios ────────────────────────────────────────────────────────────────────────────────────────────────────

SCENARIOS: list["Scenario"] = []


class Scenario:
    """One thing to show: its items of annex B, where the key may be, and what to run and expect."""

    def __init__(self, sid, items, keys, titles, run):
        self.id, self.items, self.keys, self.titles, self.run = sid, items, keys, dict(zip(LANGS, titles)), run


def scenario(sid: str, items: list[str], keys: str, en: str, es: str):
    """Registers a scenario. keys: 'signing' (once per key source asked for), 'pkcs11', 'remote', or 'none'."""
    def register(function):
        SCENARIOS.append(Scenario(sid, items, keys, (en, es), function))
        return function
    return register


# -- 4.2 Signing: the trusted list ---------------------------------------------------------------------------------

@scenario("tsl-vigente", ["F-1", "F-3"], "signing",
          "With the list signed and current, and the root listed, it signs",
          "Con la TSL firmada y vigente, y la raíz listada, se firma")
def _(r):
    r.sign("rsa-2048").signed()


@scenario("tsl-otro-firmante", ["F-1", "F-15"], "signing",
          "List signed by a certificate other than the AAC's: nothing is signed",
          "TSL firmada por un certificado que no es el de la AAC: no se firma")
def _(r):
    with r.faults(trustedList="WrongSigner"):
        r.sign("rsa-2048").fails("not signed by the scheme operator")
    r.audit_has(signed=False, message="AgentNotOpened")


@scenario("tsl-alterada", ["F-1"], "signing",
          "List changed after it was signed: nothing is signed",
          "TSL alterada después de firmada: no se firma")
def _(r):
    with r.faults(trustedList="Tampered"):
        r.sign("rsa-2048").fails_with("list was refused", "trusted list")
    r.audit_has(signed=False, message="AgentNotOpened")


@scenario("tsl-expirada", ["F-2"], "signing",
          "Expired list: nothing is signed",
          "TSL expirada: no se firma")
def _(r):
    with r.faults(trustedList="Expired"):
        r.sign("rsa-2048").fails("trusted list expired")
    r.audit_has(signed=False, message="AgentNotOpened")


@scenario("raiz-no-listada", ["F-3"], "signing",
          "The signer's root CA is not among the trusted roots: nothing is signed",
          "La EC raíz del firmante no está en la lista de confianza: no se firma")
def _(r):
    r.sign("rsa-2048", trust=["--trust-root", r.other_root()]).error("UntrustedRoot")


# -- 4.2 Signing: revocation ---------------------------------------------------------------------------------------

@scenario("crl-http", ["F-5", "F-8"], "signing",
          "CRL fetched over HTTP (no OCSP available): it signs",
          "Consulta de CRL por HTTP (sin OCSP disponible): se firma")
def _(r):
    with r.faults(ocsp="Down"):
        r.sign("rsa-2048").signed()
    r.sandbox_saw("crl")


@scenario("crl-https", ["F-5"], "signing",
          "Certificate whose CRL is published over HTTPS only: it signs",
          "Certificado cuya CRL se publica solo por HTTPS: se firma")
def _(r):
    r.sign("good-crl-https").signed()


@scenario("crl-ldap", ["F-5"], "signing",
          "Certificate whose CRL is published over LDAP only: it signs",
          "Certificado cuya CRL se publica solo por LDAP: se firma")
def _(r):
    r.sign("good-crl-ldap").signed()


@scenario("crl-clave-ajena", ["F-6"], "signing",
          "CRL signed with a key that is not the CA's: nothing is signed",
          "CRL firmada con una clave que no es la de la EC: no se firma")
def _(r):
    with r.faults(crl="WrongKey", ocsp="Down"):
        r.sign("rsa-2048").error("RevocationStatusUnknown")


@scenario("crl-expirada", ["F-7"], "signing",
          "Expired CRL: nothing is signed",
          "CRL vencida: no se firma")
def _(r):
    with r.faults(crl="Expired", ocsp="Down"):
        r.sign("rsa-2048").error("RevocationStatusUnknown")


@scenario("crl-sin-proxima-actualizacion", ["F-7"], "signing",
          "CRL without a next update: nothing is signed",
          "CRL sin fecha de próxima actualización: no se firma")
def _(r):
    with r.faults(crl="NoNextUpdate", ocsp="Down"):
        r.sign("rsa-2048").error("RevocationStatusUnknown")


@scenario("revocado", ["F-8"], "signing",
          "Revoked certificate (CRL over HTTP and OCSP): it does not sign",
          "Certificado revocado (CRL por HTTP y OCSP): no firma")
def _(r):
    r.sign("revoked").error("CertificateRevoked")
    r.audit_has(signed=False, reason="CertificateRevoked")


@scenario("revocado-crl-https", ["F-5", "F-8"], "signing",
          "Revoked certificate, CRL over HTTPS only: it does not sign",
          "Certificado revocado, CRL solo por HTTPS: no firma")
def _(r):
    r.sign("revoked-crl-https").error("CertificateRevoked")


@scenario("revocado-crl-ldap", ["F-5", "F-8"], "signing",
          "Revoked certificate, CRL over LDAP only: it does not sign",
          "Certificado revocado, CRL solo por LDAP: no firma")
def _(r):
    r.sign("revoked-crl-ldap").error("CertificateRevoked")


@scenario("revocacion-no-disponible", ["F-8", "F-14"], "signing",
          "Neither the CRL nor OCSP answers: nothing is signed",
          "Ni la CRL ni OCSP responden: no se firma")
def _(r):
    with r.faults(crl="Down", ocsp="Down"):
        r.sign("rsa-2048").error("RevocationStatusUnknown")
    r.audit_has(signed=False, reason="RevocationStatusUnknown")


@scenario("cadena-revocada", ["F-9"], "signing",
          "The issuing CA is revoked: nothing is signed",
          "La EC emisora está revocada: no se firma")
def _(r):
    r.sign("under-revoked-ca").error("CertificateRevoked")


@scenario("ocsp-vigente", ["F-10"], "signing",
          "Certificate with OCSP only, status good: it signs",
          "Certificado con OCSP solamente, estado bueno: se firma")
def _(r):
    r.sign("good-ocsp").signed()
    r.sandbox_saw("ocsp")


@scenario("ocsp-revocado", ["F-10"], "signing",
          "Certificate with OCSP only, revoked: it does not sign",
          "Certificado con OCSP solamente, revocado: no firma")
def _(r):
    r.sign("revoked-ocsp").error("CertificateRevoked")


@scenario("ocsp-no-autorizado", ["F-10"], "signing",
          "OCSP response signed by a responder the CA never authorized: nothing is signed",
          "Respuesta OCSP firmada por quien la EC no autorizó: no se firma")
def _(r):
    with r.faults(ocsp="Unauthorized"):
        r.sign("good-ocsp").error("RevocationStatusUnknown")


# -- 4.2 Signing: validity and purpose -----------------------------------------------------------------------------

@scenario("expirado", ["F-11"], "signing",
          "Expired certificate: it does not sign",
          "Certificado expirado: no firma")
def _(r):
    r.sign("expired").error("CertificateExpired")


@scenario("aun-no-valido", ["F-11"], "signing",
          "Certificate not yet valid: it does not sign",
          "Certificado cuya vigencia aún no comienza: no firma")
def _(r):
    r.sign("not-yet-valid").error("CertificateNotCurrentlyValid")


@scenario("ec-expirada", ["F-11"], "signing",
          "The issuing CA expired: nothing is signed",
          "La EC emisora expiró: no se firma")
def _(r):
    r.sign("under-expired-ca").error("ChainCertificateNotValid")


@scenario("sin-no-repudio", ["F-12"], "signing",
          "Certificate without the nonRepudiation bit: it does not sign",
          "Certificado sin el bit nonRepudiation: no firma")
def _(r):
    r.sign("no-nonrepudiation").error("KeyUsageNotPermitted")


@scenario("sin-uso-de-firma", ["F-12"], "signing",
          "Certificate without a signing key usage (keyEncipherment only): it does not sign",
          "Certificado sin uso de clave para firmar (keyEncipherment solamente): no firma")
def _(r):
    r.sign("no-signing-key-usage").error("KeyUsageNotPermitted")


# -- 4.2 Signing: nothing to switch off, audit, transactions -------------------------------------------------------

@scenario("sin-opcion-de-politica", ["F-14"], "none",
          "There is no option to change the policy or skip a check: such an option is an error",
          "No hay opción para cambiar la política ni saltar una verificación: una opción así es un error")
def _(r):
    for option in (["--signing-policy", "minimal"], ["--no-revocation-check"], ["--profile", "sandbox"]):
        r.sign("rsa-2048", key="any", extra=option).fails("Unknown option " + option[0])
    r.cli(["iofe", "sign", "--help"]).ok().lacks("--signing-policy", "--policy ", "--skip")


@scenario("contingencia", ["F-14"], "signing",
          "No CRL nor OCSP: it signs only under a declared contingency, which goes to the record",
          "Sin CRL ni OCSP: solo bajo una contingencia declarada se firma, y queda en el registro")
def _(r):
    with r.faults(crl="Down", ocsp="Down"):
        r.sign("rsa-2048").error("RevocationStatusUnknown")
        r.sign("rsa-2048", contingency=("PROC-AAC-07", +2)).signed()
    r.audit_has(signed=True, policy="PROC-AAC-07")


@scenario("contingencia-revocado", ["F-14"], "signing",
          "Under a contingency a revoked certificate still does not sign",
          "Bajo contingencia, un certificado revocado sigue sin firmar")
def _(r):
    r.sign("revoked", contingency=("PROC-AAC-07", +2)).error("CertificateRevoked")


@scenario("contingencia-vencida", ["F-14"], "signing",
          "Contingency outside its validity: refused",
          "Contingencia fuera de su vigencia: se rechaza")
def _(r):
    r.sign("rsa-2048", contingency=("PROC-AAC-07", -2)).refused("ContingencyExpired")


@scenario("auditoria", ["F-15"], "signing",
          "Every signature made or refused is recorded; the chain of records shows a change",
          "Cada firma hecha o rechazada queda registrada; la cadena de registros evidencia una alteración")
def _(r):
    r.sign("rsa-2048", transaction="factura/F001-1").signed()
    if r.can_sign("revoked"):
        refused = "factura/F001-2"
        r.sign("revoked", transaction=refused).error("CertificateRevoked")
    else:
        refused = "contrato/F001-2"
        r.sign("rsa-2048", transaction=refused).refused("TransactionNotAllowed")
    r.sign("rsa-2048", transaction="constancia/C-9").signed()
    r.audit_count(3)
    r.audit_has(signed=True, operation="factura/F001-1")
    r.audit_has(signed=False, operation=refused)
    r.cli(["audit", "verify", r.audit_log]).ok().has("Intact")
    r.cli(["audit", "verify", r.tampered_copy(r.audit_log)]).fails()


@scenario("sin-registro-de-auditoria", ["F-15"], "none",
          "Without an audit log nothing is signed",
          "Sin registro de auditoría no se firma")
def _(r):
    r.sign("rsa-2048", key="any", audit=False).fails("--audit-log is required")


@scenario("transaccion-no-definida", ["F-16"], "signing",
          "A transaction of a kind the agent was not set up for: refused and recorded",
          "Transacción de un tipo que el agente no tiene definido: se rechaza y se registra")
def _(r):
    r.sign("rsa-2048", transaction="contrato/X-9").refused("TransactionNotAllowed")
    r.audit_has(signed=False, operation="contrato/X-9")


# -- 4.2 Signing: where the key is ---------------------------------------------------------------------------------

@scenario("clave-en-el-modulo", ["F-17", "F-18"], "pkcs11",
          "The key signs inside the PKCS#11 module, which reports it sensitive and not extractable",
          "La clave firma dentro del módulo PKCS#11, que la declara sensible y no extraíble")
def _(r):
    r.sign("rsa-2048").signed().has("sensitive: True", "extractable: False")


@scenario("clave-extraible", ["F-18"], "pkcs11",
          "A key the module reports as extractable: refused",
          "Clave que el módulo declara extraíble: se rechaza")
def _(r):
    r.sign("extractable").refused("KeyNotInModule")
    r.audit_has(signed=False, message="KeyNotInModule")


@scenario("modulo-no-declarado", ["F-19"], "pkcs11",
          "The token is not the module the operator declared: refused",
          "El token no es el módulo declarado por el operador: se rechaza")
def _(r):
    r.sign("rsa-2048", module=OTHER_MODULE).refused("ModuleMismatch")
    r.audit_has(signed=False, message="ModuleMismatch")


@scenario("clave-en-el-servicio-remoto", ["F-17", "F-18"], "remote",
          "The key signs in the remote signing service: the application sends the hash only",
          "La clave firma en el servicio de firma remota: la aplicación solo envía el resumen")
def _(r):
    r.sign("rsa-2048").signed().has("in the remote service")
    r.sandbox_saw("csc")
    r.audit_has(signed=True, policy="firma remota")


@scenario("servicio-no-declarado", ["F-19"], "remote",
          "The remote signing service is not the declared one: refused before any secret is sent to it",
          "El servicio de firma remota no es el declarado: se rechaza antes de enviarle secreto alguno")
def _(r):
    r.sign("rsa-2048", service_name="Otro Servicio").refused("RemoteServiceMismatch")
    r.audit_has(signed=False, message="RemoteServiceMismatch")


@scenario("credencial-con-persona", ["F-16"], "remote",
          "A remote credential a person has to authorize: an unattended agent refuses it",
          "Credencial remota que debe autorizar una persona: un agente desatendido la rechaza")
def _(r):
    r.sign("rsa-2048", credential="rsa-oauth").refused("RemoteAuthorizationNotUnattended")


@scenario("pin-incorrecto", ["F-15", "F-17"], "signing",
          "Wrong PIN: nothing is signed, and the attempt is recorded",
          "PIN incorrecto: no se firma, y el intento queda registrado")
def _(r):
    r.sign("rsa-2048", pin="9999").fails()
    r.audit_lacks_signed()
    r.audit_has(signed=False)


@scenario("pfx-no-aceptado", ["F-17", "F-18"], "none",
          "A PKCS#12 (PFX) file is not a key source: there is no option to use one",
          "Un archivo PKCS#12 (PFX) no es una fuente de clave: no hay opción para usarlo")
def _(r):
    pfx, password = r.pfx("rsa-2048")
    r.sign("rsa-2048", key=None, extra=["--cert", pfx, "--password", password]).fails(
        "--pkcs11-lib (a cryptographic module) or --csc-url (a remote signing service)")
    r.sign("rsa-2048", key="any", extra=["--cert", pfx]).fails("Unknown option --cert")
    r.cli(["iofe", "sign", "--help"]).ok().lacks("--cert ", "--password")


# -- 4.2 Signing: algorithms, viewer, validation data --------------------------------------------------------------

@scenario("clave-debil", ["F-28"], "signing",
          "RSA 1024-bit key: it does not sign",
          "Clave RSA de 1024 bits: no firma")
def _(r):
    r.sign("rsa-1024").error("KeyTooWeak")


@scenario("sha1-en-la-cadena", ["F-28"], "signing",
          "A chain with a certificate signed with SHA-1: nothing is signed",
          "Cadena con un certificado firmado con SHA-1: no se firma")
def _(r):
    r.sign("under-sha1-ca").error("AlgorithmNotPermitted").has("SHA1")


@scenario("algoritmos-vigentes", ["F-28"], "signing",
          "RSA 3072 and 4096, ECDSA P-256 and P-384: it signs",
          "RSA 3072 y 4096, ECDSA P-256 y P-384: se firma")
def _(r):
    for signer in r.keys_among("rsa-3072", "rsa-4096", "ecdsa-p256", "ecdsa-p384"):
        r.sign(signer).signed()


@scenario("visor", ["F-30"], "signing",
          "The viewer shows integrity, signing time, public key and certificate data",
          "El visor muestra integridad, fecha y hora, clave pública y datos del certificado")
def _(r):
    step = r.sign("rsa-2048").signed().names_signer()
    page = r.path("visor.html")
    r.cli(["iofe", "view", step.output, "--output", page] + r.trust()).ok()
    r.file_has(page, step.signer, "BEGIN PUBLIC KEY")


@scenario("datos-de-validacion", ["F-31", "S-1", "S-2", "S-3", "S-4"], "signing",
          "With the time-stamp authority: token checked, chain and revocation data embedded (B-LT)",
          "Con la autoridad de sellado de tiempo: sello verificado, cadena y datos de revocación incluidos (B-LT)")
def _(r):
    signed = r.sign("rsa-2048", tsa="tsa").signed().has("LongTerm").output
    r.cli(["inspect", signed]).ok().has("Timestamp")
    r.verify(signed).accepted()


@scenario("formatos", ["F-31"], "signing",
          "Signature of XML (XAdES) and of any file (CMS, CAdES), which the verification agent accepts",
          "Firma de XML (XAdES) y de cualquier archivo (CMS, CAdES), que el agente de verificación acepta")
def _(r):
    xml = r.sign("rsa-2048", document="xml").signed().output
    cms = r.sign("rsa-2048", document="bin").signed().output
    r.verify(xml).accepted()
    r.verify(cms).accepted()


# -- 4.4 Time-stamps -----------------------------------------------------------------------------------------------

@scenario("tsa-otra-autoridad", ["S-1"], "signing",
          "The token comes from another authority than the one configured: refused",
          "El sello proviene de otra autoridad que la configurada: se rechaza")
def _(r):
    r.sign("rsa-2048", tsa="other").error("TimestampUntrusted").has("not by the expected TSA")


@scenario("tsa-sello-alterado", ["S-2"], "signing",
          "A time-stamp whose signature was changed: refused",
          "Sello de tiempo con la firma alterada: se rechaza")
def _(r):
    with r.faults(tsa="InvalidToken"):
        r.sign("rsa-2048", tsa="tsa").error("TimestampInvalid").has("token signature")


@scenario("tsa-revocada", ["S-3"], "signing",
          "The time-stamp authority's certificate is revoked: refused",
          "Certificado de la autoridad de sellado de tiempo revocado: se rechaza")
def _(r):
    r.sign("rsa-2048", tsa="revoked").error("TimestampCertificateRevoked")


@scenario("tsa-expirada", ["S-4"], "signing",
          "The time-stamp authority's certificate expired: refused",
          "Certificado de la autoridad de sellado de tiempo expirado: se rechaza")
def _(r):
    r.sign("rsa-2048", tsa="expired").error("TimestampCertificateNotValid")


# -- 4.3 Verification ----------------------------------------------------------------------------------------------

@scenario("v-valido", ["V-1", "V-3", "V-5", "V-10", "V-11", "V-12", "V-15"], "none",
          "A document validly signed with a certificate of the list: accepted and recorded",
          "Documento con firma válida de un certificado de la lista: se acepta y se registra")
def _(r):
    r.verify(r.sample("rsa-2048")).accepted()
    r.verification_has(accepted=True)


@scenario("v-tsl-otro-firmante", ["V-1"], "none",
          "List signed by another certificate: the verification does not go on",
          "TSL firmada por otro certificado: la verificación no se realiza")
def _(r):
    sample = r.sample("rsa-2048")
    with r.faults(trustedList="WrongSigner"):
        r.verify(sample).fails("not signed by the scheme operator")


@scenario("v-tsl-expirada", ["V-2"], "none",
          "Expired list: the document is not accepted",
          "TSL expirada: el documento no se acepta")
def _(r):
    sample = r.sample("rsa-2048")
    with r.faults(trustedList="Expired"):
        r.verify(sample).fails("trusted list expired")


@scenario("v-raiz-no-listada", ["V-3"], "none",
          "A signer whose root CA is not trusted: rejected",
          "Firmante cuya EC raíz no está entre las de confianza: se rechaza")
def _(r):
    r.verify(r.sample("rsa-2048"), trust=["--trust-root", r.other_root()]).rejected("NoCertificateChainFound")


@scenario("v-revocado", ["V-5", "V-8", "V-9", "V-10"], "none",
          "A document signed with a certificate revoked afterwards: rejected, with a notice to its sender",
          "Documento firmado con un certificado que luego fue revocado: se rechaza, con comunicado al emisor")
def _(r):
    r.verify(r.sample("revoked")).rejected("RevokedNoPoe")
    r.notice_has(SENDER)
    r.verification_has(accepted=False)


@scenario("v-revocado-crl-https", ["V-5"], "none",
          "A revoked signer whose CRL is published over HTTPS only: rejected",
          "Firmante revocado cuya CRL se publica solo por HTTPS: se rechaza")
def _(r):
    r.verify(r.sample("revoked-crl-https")).rejected("RevokedNoPoe")


@scenario("v-revocado-crl-ldap", ["V-5"], "none",
          "A revoked signer whose CRL is published over LDAP only: rejected",
          "Firmante revocado cuya CRL se publica solo por LDAP: se rechaza")
def _(r):
    r.verify(r.sample("revoked-crl-ldap")).rejected("RevokedNoPoe")


@scenario("v-crl-clave-ajena", ["V-6"], "none",
          "CRL signed with a key that is not the CA's: the document is not accepted",
          "CRL firmada con una clave que no es la de la EC: el documento no se acepta")
def _(r):
    sample = r.sample("rsa-2048")
    with r.faults(crl="WrongKey", ocsp="Down"):
        r.verify(sample).rejected("CertificateChainGeneralFailure")


@scenario("v-crl-expirada", ["V-7"], "none",
          "Expired CRL: the document is not accepted",
          "CRL vencida: el documento no se acepta")
def _(r):
    sample = r.sample("rsa-2048")
    with r.faults(crl="Expired", ocsp="Down"):
        r.verify(sample).rejected("CertificateChainGeneralFailure")


@scenario("v-cadena-revocada", ["V-9"], "none",
          "The signer's issuing CA is revoked: rejected",
          "La EC emisora del firmante está revocada: se rechaza")
def _(r):
    r.verify(r.sample("under-revoked-ca")).rejected("RevokedCaNoPoe")


@scenario("v-ocsp-revocado", ["V-10"], "none",
          "A signer with OCSP only, revoked: rejected",
          "Firmante con OCSP solamente, revocado: se rechaza")
def _(r):
    r.verify(r.sample("revoked-ocsp")).rejected("RevokedNoPoe")


@scenario("v-expirado", ["V-11"], "none",
          "A document signed with a certificate that has expired: rejected",
          "Documento firmado con un certificado que ya expiró: se rechaza")
def _(r):
    r.verify(r.expired_sample()).rejected("OutOfBoundsNoPoe")


@scenario("v-sin-no-repudio", ["V-12"], "none",
          "A signer without the nonRepudiation bit: rejected",
          "Firmante sin el bit nonRepudiation: se rechaza")
def _(r):
    r.verify(r.sample("no-nonrepudiation")).rejected("ChainConstraintsFailure")


@scenario("v-sin-opcion-de-politica", ["V-14"], "none",
          "There is no option to change the verification policy: such an option is an error",
          "No hay opción para cambiar la política de verificación: una opción así es un error")
def _(r):
    r.verify(r.sample("rsa-2048"), extra=["--policy", "default"]).fails("Unknown option --policy")
    r.cli(["iofe", "verify", "--help"]).ok().lacks("--policy ", "--skip")


@scenario("v-contingencia", ["V-14"], "none",
          "No CRL nor OCSP: rejected; under a declared contingency it is accepted and recorded",
          "Sin CRL ni OCSP: se rechaza; bajo una contingencia declarada se acepta y queda en el registro")
def _(r):
    sample = r.sample("rsa-2048")
    with r.faults(crl="Down", ocsp="Down"):
        r.verify(sample).rejected("CertificateChainGeneralFailure")
        r.verify(sample, contingency=("PROC-AAC-07", +2)).accepted()


@scenario("v-contingencia-revocado", ["V-14"], "none",
          "Under a contingency a revoked signer is still rejected",
          "Bajo contingencia, un firmante revocado sigue rechazado")
def _(r):
    r.verify(r.sample("revoked"), contingency=("PROC-AAC-07", +2)).rejected("RevokedNoPoe")


@scenario("v-auditoria", ["V-15"], "none",
          "Every verification, accepted or rejected, is recorded; the chain shows a change",
          "Cada verificación, aceptada o rechazada, queda registrada; la cadena evidencia una alteración")
def _(r):
    r.verify(r.sample("rsa-2048")).accepted()
    if r.received("revoked"):
        r.verify(r.sample("revoked")).rejected("RevokedNoPoe")
    else:
        r.verify(r.changed_copy(r.sample("rsa-2048"))).rejected("HashFailure")
    r.verification_count(2)
    r.cli(["audit", "verify", r.verification_log]).ok().has("Intact")
    r.cli(["audit", "verify", r.tampered_copy(r.verification_log)]).fails()


@scenario("v-clave-debil", ["V-28"], "none",
          "A signer with an RSA 1024-bit key: rejected",
          "Firmante con clave RSA de 1024 bits: se rechaza")
def _(r):
    r.verify(r.sample("rsa-1024")).rejected("CryptoConstraintsFailureNoPoe")


@scenario("v-documento-alterado", ["V-30"], "none",
          "A document changed after it was signed: rejected, with a notice to its sender",
          "Documento alterado después de la firma: se rechaza, con comunicado al emisor")
def _(r):
    r.verify(r.changed_copy(r.sample("rsa-2048"))).rejected("HashFailure")
    r.notice_has(SENDER)


@scenario("v-sin-firmas", ["V-30"], "none",
          "A document without signatures: rejected, with a notice to its sender",
          "Documento sin firmas: se rechaza, con comunicado al emisor")
def _(r):
    r.verify(r.document("pdf")).rejected().has("no contiene firmas")
    r.notice_has(SENDER)


@scenario("v-visor", ["V-30"], "none",
          "The viewer shows the data of the signature of a received document",
          "El visor muestra los datos de la firma de un documento recibido")
def _(r):
    page = r.path("visor.html")
    sample = r.sample("rsa-2048")
    r.cli(["iofe", "view", sample, "--output", page] + r.trust()).ok()
    r.file_has(page, r.signer_of_sample("rsa-2048") or "BEGIN PUBLIC KEY")


# ── The run ──────────────────────────────────────────────────────────────────────────────────────────────────────

class Problem(Exception):
    """The environment is not what the script needs."""


class Unavailable(Exception):
    """The environment cannot show a scenario: what the scenario asks for is not there. Not a failure of anything."""

    def __init__(self, key, detail=None):
        super().__init__(key if detail is None else f"{key}: {detail}")
        self.reason = {"key": key, "detail": detail} if detail else {"key": key}


def signer_in(text):
    """The common name of the subject `iofe sign` printed as the signer; empty when it printed none."""
    line = next((line for line in text.splitlines() if line.strip().startswith("Signer")), "")
    subject = line.strip()[len("Signer"):].strip()
    name = re.search(r"CN=((?:[^,\\]|\\.)+)", subject)
    return (name.group(1).replace("\\", "") if name else subject).strip()


class Check:
    def __init__(self, expected, found, ok):
        self.expected, self.found, self.ok = expected, found, ok


class Step:
    """One command and what was expected of it."""

    def __init__(self, run, command, exit_code, text, output=None):
        self.run, self.command, self.exit, self.text, self.output = run, command, exit_code, text, output
        self.flat = " ".join(text.split())
        self.checks: list[Check] = []

    def _check(self, expected, ok, found=None):
        self.checks.append(Check(expected, found if found is not None else self._summary(), ok))
        self.run.show_check(self.checks[-1])
        return self

    def _summary(self):
        first = next((line.strip() for line in self.text.splitlines() if line.strip()), "")
        return f"exit {self.exit}: {' '.join(self.flat.split()[:28])}" if first else f"exit {self.exit}"

    def _no_output(self):
        if self.output is not None:
            exists = os.path.exists(self.output)
            self._check({"key": "exp_no_file"}, not exists, {"key": "no" if not exists else "yes"})
        return self

    def ok(self):
        return self._check({"key": "exp_ok"}, self.exit == 0)

    def signed(self):
        self._check({"key": "exp_signed"}, self.exit == 0 and "Signed" in self.flat)
        if self.output is not None:
            exists = os.path.exists(self.output)
            self._check({"key": "exp_file"}, exists, {"key": "yes" if exists else "no"})
        return self

    def refused(self, reason):
        return self._check({"key": "exp_refused", "detail": f"Refused ({reason})"},
                           self.exit != 0 and f"Refused ({reason})" in self.flat)._no_output()

    def error(self, *reasons):
        """Refused by the signing policy with one of these reasons."""
        hit = any(f"Error ({reason})" in self.flat for reason in reasons)
        return self._check({"key": "exp_refused", "detail": " | ".join(f"Error ({r})" for r in reasons)},
                           self.exit != 0 and hit)._no_output()

    def fails(self, *texts):
        hit = all(text.lower() in self.flat.lower() for text in texts)
        return self._check({"key": "exp_fails", "detail": " + ".join(texts)}, self.exit != 0 and hit)._no_output()

    def accepted(self):
        return self._check({"key": "exp_accepted"}, self.exit == 0 and "Accepted" in self.flat)

    def rejected(self, reason=None):
        """Rejected by the verification agent, for this reason (the sub-indication of ETSI EN 319 102-1) when given."""
        ok = self.exit == 1 and "Rejected" in self.flat and (reason is None or f"({reason})" in self.flat)
        self._check({"key": "exp_rejected", "detail": reason} if reason else {"key": "exp_rejected"}, ok)
        notice = self.run.notice
        exists = os.path.exists(notice) and os.path.getsize(notice) > 0
        return self._check({"key": "exp_file", "detail": os.path.basename(notice)}, exists,
                           {"key": "yes" if exists else "no"})

    def fails_with(self, *texts):
        """The command fails, saying one of these."""
        hit = any(text.lower() in self.flat.lower() for text in texts)
        return self._check({"key": "exp_fails", "detail": " | ".join(texts)}, self.exit != 0 and hit)._no_output()

    @property
    def signer(self):
        """The name of the signer as `iofe sign` printed it: the common name of the certificate's subject."""
        return signer_in(self.text)

    def names_signer(self):
        return self._check({"key": "exp_signer"}, bool(self.signer), self.signer or None)

    def has(self, *texts):
        for text in texts:
            self._check({"key": "exp_text", "detail": text}, text.lower() in self.flat.lower())
        return self

    def lacks(self, *texts):
        for text in texts:
            self._check({"key": "exp_text", "detail": f"≠ {text.strip()}"}, text.lower() not in self.text.lower(),
                        {"key": "no" if text.lower() not in self.text.lower() else "yes"})
        return self


class DryStep:
    """A command that was not run: the scenario is only being asked what it needs. Every expectation is taken."""

    def __init__(self, output=None):
        self.output, self.text, self.flat, self.exit, self.signer, self.checks = output, "", "", 0, "", []

    def __getattr__(self, name):
        return lambda *arguments, **named: self


class Run:
    """One scenario, with one key source: its folder, its commands and what they showed."""

    def __init__(self, audit, scn, key, number, dry=False):
        self.audit_env, self.scenario, self.key, self.dry = audit, scn, key, dry
        suffix = "" if key in (None, "none") else f"-{key}"
        self.folder = audit.out / f"{number:02d}-{scn.id}{suffix}"
        if not dry:
            self.folder.mkdir(parents=True, exist_ok=True)
        self.trust_override = None
        self.audit_log = str(self.folder / "auditoria.jsonl")
        self.verification_log = str(self.folder / "verificacion.jsonl")
        self.notice = str(self.folder / "comunicado.txt")
        self.steps: list[Step] = []
        self.extra_checks: list[Check] = []
        self.sandbox_changes: list[str] = []
        self.error = None
        self._outputs = 0

    # -- what a scenario says ------------------------------------------------------------------------------------

    def path(self, name):
        return str(self.folder / name)

    def document(self, kind="pdf"):
        return self.audit_env.document(kind)

    def trust(self):
        return list(self.audit_env.trust if self.trust_override is None else self.trust_override)

    def other_root(self):
        return self.audit_env.other_root()

    def pfx(self, signer):
        """A PKCS#12 file and its password: what `iofe sign` is shown to have no option for."""
        return self.audit_env.pfx(signer)

    def sample(self, signer):
        return self.audit_env.sample(signer, self.dry)

    def expired_sample(self):
        return self.audit_env.expired_sample(self.dry)

    def can_sign(self, signer):
        """Whether the environment has a key with that certificate."""
        return self.audit_env.has_key(signer)

    def received(self, signer):
        """Whether the environment has a document a third party signed with that certificate."""
        return self.audit_env.has_received(signer)

    def keys_among(self, *signers):
        """Those of these certificates the environment has a key for; a scenario with none of them is not run."""
        found = [signer for signer in signers if self.audit_env.has_key(signer)]
        if not found:
            raise Unavailable("na_key", " | ".join(signers))
        return found

    def signer_of_sample(self, signer):
        """The name of who signed the environment's sample of that certificate; empty when it is not known."""
        return self.audit_env.sample_signer(signer)

    @contextlib.contextmanager
    def faults(self, **faults):
        """A failure of a third party while the block runs."""
        with self.audit_env.fault(self, faults):
            yield

    def cli(self, arguments, output=None):
        if self.dry:
            return DryStep(output)
        mark = self.audit_env.log_mark()
        command, code, text = self.audit_env.run_cli(arguments)
        step = Step(self, command, code, text, output)
        step.sandbox_requests = self.audit_env.log_since(mark)
        self.steps.append(step)
        self.say("$ " + command)
        if self.audit_env.verbose or self.audit_env.live:
            for line in text.rstrip().splitlines():
                self.say("    " + line)
        return step

    def sign(self, signer, key="default", document="pdf", transaction="factura/F001-123", allow=("factura", "constancia"),
             trust=None, tsa=None, contingency=None, extra=(), audit=True, module=None,
             service_name=None, credential=None, pin=None):
        """
        `iofe sign` with the key of a certificate. key: the run's own source ("default"), whichever the environment
        has ("any"), or none. tsa: the authority ("tsa"), the same one named by another certificate ("other"), or
        one whose certificate is revoked or expired.
        """
        env = self.audit_env
        key = self.key if key == "default" else env.any_key() if key == "any" else key
        if pin and not env.permits(self.scenario.id):
            raise Unavailable("na_allow")
        self._outputs += 1
        extension = {"pdf": "pdf", "xml": "xml", "bin": "p7s"}[document]
        output = self.path(f"firmado-{self._outputs}.{extension}")
        arguments = ["iofe", "sign", env.document(document), "--output", output,
                     "--transaction", transaction]
        for kind in allow:
            arguments += ["--allow", kind]
        if audit:
            arguments += ["--audit-log", self.audit_log]
        arguments += list(trust) if trust is not None else self.trust()
        if key == "remote":
            arguments += env.remote_arguments(credential or env.credential(signer), service_name, pin)
        elif key == "pkcs11":
            arguments += env.pkcs11_arguments(signer, module, pin)
        if tsa:
            arguments += env.tsa_arguments(tsa)
        if contingency:
            arguments += env.contingency_arguments(*contingency)
        step = self.cli(arguments + list(extra), output)
        if not self.dry and step.exit == 0 and step.signer:
            env.signer_names.setdefault(signer, step.signer)
        return step

    def verify(self, document, trust=None, contingency=None, extra=()):
        env = self.audit_env
        if os.path.exists(self.notice):
            os.remove(self.notice)
        arguments = ["iofe", "verify", document, "--sender", SENDER, "--contact", "mesa.de.partes@entidad.example",
                     "--reference", "expediente 2026-001", "--audit-log", self.verification_log, "--notice", self.notice]
        arguments += list(trust) if trust is not None else self.trust()
        if contingency:
            arguments += env.contingency_arguments(*contingency)
        return self.cli(arguments + list(extra))

    # -- checks beyond a command's output ------------------------------------------------------------------------

    def _extra(self, expected, ok, found):
        if self.dry:
            return
        self.extra_checks.append(Check(expected, found, ok))
        self.show_check(self.extra_checks[-1])

    @staticmethod
    def _records(path):
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8-sig") as lines:
            return [json.loads(line) for line in lines if line.strip()]

    def audit_count(self, count):
        records = self._records(self.audit_log)
        self._extra({"key": "exp_audit", "detail": f"× {count}"}, len(records) == count, f"× {len(records)}")

    def audit_has(self, signed, operation=None, reason=None, message=None, policy=None):
        def matches(record):
            return (record.get("signed") == signed
                    and (operation is None or record.get("operationId") == operation)
                    and (reason is None or reason in str(record.get("reason")))
                    and (message is None or message in str(record.get("message")))
                    and (policy is None or policy in str(record.get("policyName"))))
        wanted = ", ".join(f"{k}={v}" for k, v in (("signed", signed), ("operationId", operation), ("reason", reason),
                                                     ("message", message), ("policyName", policy)) if v is not None)
        records = self._records(self.audit_log)
        last = records[-1] if records else {}
        found = ", ".join(f"{k}={last.get(k)}" for k in ("signed", "operationId", "reason", "policyName") if k in last)
        self._extra({"key": "exp_audit", "detail": wanted}, any(matches(record) for record in records), found or "—")

    def audit_lacks_signed(self):
        records = self._records(self.audit_log)
        signed = [record for record in records if record.get("signed")]
        self._extra({"key": "exp_audit", "detail": "signed=True × 0"}, not signed, f"signed=True × {len(signed)}")

    def verification_count(self, count):
        records = self._records(self.verification_log)
        self._extra({"key": "exp_audit", "detail": f"× {count}"}, len(records) == count, f"× {len(records)}")

    def verification_has(self, accepted):
        records = self._records(self.verification_log)
        last = records[-1] if records else {}
        self._extra({"key": "exp_audit", "detail": f"accepted={accepted}"},
                    any(record.get("accepted") == accepted for record in records),
                    f"accepted={last.get('accepted')}" if last else "—")

    def notice_has(self, text):
        content = pathlib.Path(self.notice).read_text(encoding="utf-8-sig") if os.path.exists(self.notice) else ""
        self._extra({"key": "exp_text", "detail": f"{os.path.basename(self.notice)}: {text}"}, text in content,
                    content.strip().splitlines()[0][:80] if content.strip() else "—")

    def file_has(self, path, *texts):
        if self.dry:
            return
        content = pathlib.Path(path).read_text(encoding="utf-8-sig", errors="replace") if os.path.exists(path) else ""
        for text in texts:
            if not text:
                self._extra({"key": "exp_signer"}, False, "—")
                continue
            self._extra({"key": "exp_text", "detail": f"{os.path.basename(path)}: {text}"}, text in content,
                        {"key": "yes" if text in content else "no"})

    def sandbox_saw(self, service):
        """The Sandbox's own log shows the agent asked that service during the last command. A real CA shows no log."""
        if self.dry or not self.audit_env.keeps_log:
            return
        requests = getattr(self.steps[-1], "sandbox_requests", []) if self.steps else []
        hits = [request for request in requests if service in str(request.get("service", "")).lower()
                or f"/{service}" in str(request.get("path", "")).lower()]
        self._extra({"key": "exp_text", "detail": f"Sandbox log: {service}"}, bool(hits),
                    f"{len(hits)} request(s)" if hits else "—")

    def tampered_copy(self, path):
        """A copy of an audit trail with one record changed."""
        copy = self.path("alterado-" + os.path.basename(path))
        if self.dry:
            return copy
        text = pathlib.Path(path).read_text(encoding="utf-8-sig")
        changed = text.replace('"signed":true', '"signed":false', 1) if '"signed":true' in text \
            else text.replace('"accepted":false', '"accepted":true', 1) if '"accepted":false' in text \
            else text.replace("factura", "FACTURA", 1)
        pathlib.Path(copy).write_text(changed, encoding="utf-8")
        return copy

    def changed_copy(self, path):
        """A copy of a signed document with one byte of what is signed changed."""
        copy = self.path("alterado-" + os.path.basename(path))
        if self.dry:
            return copy
        data = bytearray(pathlib.Path(path).read_bytes())
        at = data.find(b"/MediaBox")
        at = at + 12 if at >= 0 else len(data) // 4
        data[at] = data[at] ^ 0x01
        pathlib.Path(copy).write_bytes(bytes(data))
        return copy

    # -- result ----------------------------------------------------------------------------------------------------

    @property
    def checks(self):
        return [check for step in self.steps for check in step.checks] + self.extra_checks

    @property
    def passed(self):
        return self.error is None and bool(self.checks) and all(check.ok for check in self.checks)

    def say(self, line):
        if not self.dry and (self.audit_env.live or self.audit_env.verbose):
            print("   " + line)

    def show_check(self, check):
        if self.audit_env.live or self.audit_env.verbose:
            lang = self.audit_env.lang
            mark = "✓" if check.ok else "✗"
            print(f"   {mark} {tr('expected', lang)}: {phrase(check.expected, lang)}"
                  + ("" if check.ok else f"  ·  {tr('found', lang)}: {phrase(check.found, lang)}"))

    def save(self):
        with open(self.folder / "comandos.txt", "w", encoding="utf-8") as out:
            for change in self.sandbox_changes:
                out.write(f"# {self.audit_env.setup_label}: {change}\n")
            for step in self.steps:
                out.write(f"$ {step.command}\n{step.text.rstrip()}\n[exit {step.exit}]\n\n")
        requests = [request for step in self.steps for request in getattr(step, "sandbox_requests", [])]
        if requests:
            (self.folder / "sandbox-log.json").write_text(json.dumps(requests, indent=1), encoding="utf-8")


def phrase(value, lang):
    """A check's expectation or finding as text: a plain string, or a key of TEXT with a detail."""
    if isinstance(value, dict):
        text = tr(value["key"], lang)
        return f"{text}: {value['detail']}" if value.get("detail") else text
    return str(value)


class Audit:
    """The environment of a run: the Sandbox, the command line, the key sources, the files."""

    real = False            # a test PKI: every certificate and every failure a scenario asks for can be made
    keeps_log = True        # the Sandbox logs what was asked of it
    setup_label = "Sandbox"

    def __init__(self, options):
        self.sandbox = options.sandbox.rstrip("/")
        self.key_option = options.key
        self.signer_names: dict[str, str] = {}
        self.cli_command = shlex.split(options.cli)
        self.out = pathlib.Path(options.out).resolve()
        self.lang, self.verbose, self.live = options.lang, options.verbose, options.live
        self.work = self.out / "_entradas"
        self.info = None
        self.environment = dict(os.environ)
        self._credentials, self._samples, self._documents = None, {}, {}
        self.pkcs11_library = options.pkcs11_lib or self._find_softhsm()
        self.trust: list[str] = []
        self.network: list[str] = []

    # -- the Sandbox -----------------------------------------------------------------------------------------------

    def api(self, method, path, body=None, raw=False):
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.sandbox + path, data=data, method=method,
                                         headers={"Content-Type": "application/json"} if data else {})
        with urllib.request.urlopen(request, timeout=60) as response:
            content = response.read()
        return content if raw else (json.loads(content) if content.strip() else None)

    def prepare(self):
        try:
            self.info = self.api("GET", "/api/info")
        except (urllib.error.URLError, OSError) as error:
            raise Problem(f"No SimpleSign Sandbox at {self.sandbox} ({error}). Start one: tools/stack/up.sh, or "
                          "dotnet run --project src/Apps/Development/SimpleSign.Sandbox") from error
        self.work.mkdir(parents=True, exist_ok=True)
        self.api("DELETE", "/api/faults")

        root = self.work / "sandbox-root.pem"
        root.write_bytes(self.api("GET", "/root.pem", raw=True))
        chain = self.work / "sandbox-chain.pem"
        chain.write_bytes(self.api("GET", "/chain.pem", raw=True))
        signer = self.work / "tsl-signer.pem"
        signer.write_bytes(self.api("GET", "/tl/tl-signer.pem", raw=True))
        # The Sandbox's list is laid out as INDECOPI's and read the same way; its signer is given as INDECOPI's is.
        self.trust = ["--tsl", self.info["trustedLists"]["tlUrl"], "--tsl-signer", str(signer)]
        # A test PKI on this machine: its addresses are allowed, LDAP too, and its chain is accepted for HTTPS.
        self.network = ["--allow-ldap", "--tls-trust", str(chain)]
        for origin in self.info.get("loopbackOrigins", [self.sandbox]):
            self.network += ["--allow-origin", origin]

        csc = self.info["csc"]
        self.environment.update({"AUD_PIN": "1234", "AUD_CSC_PIN": csc["pin"], "AUD_CSC_SECRET": csc["clientSecret"],
                                 "NO_COLOR": "1"})
        command, code, text = self.run_cli(["iofe", "--help"])
        if code != 0:
            raise Problem(f"`{command}` failed: is the IOFE extension installed? "
                          "(simplesign extension install SimpleSign.Peru.Iofe.Cli)\n" + text)
        reported = json.loads(self._post(csc["baseUrl"] + "info", {}))
        self.service_name = reported.get("name", "")

    # -- what a scenario may ask -------------------------------------------------------------------------------------

    def sources(self):
        """Where the key is, in this run."""
        return ["remote", "pkcs11"] if self.key_option == "both" else [self.key_option]

    def any_key(self):
        """The key source of a scenario that is not about where the key is."""
        return "remote"

    def permits(self, scenario_id):
        """Whether a scenario that acts on the module (a wrong PIN) may run."""
        return True

    def has_key(self, signer):
        return True

    def has_received(self, signer):
        return True

    def sample_signer(self, signer):
        return "Maria da Silva"

    def where(self):
        return f"Sandbox {self.sandbox} ({self.info.get('version', '')})"

    def reset(self):
        self.api("DELETE", "/api/faults")

    def describe(self):
        """What is kept about the environment itself: nothing for a Sandbox, which the report already names."""
        return []

    @contextlib.contextmanager
    def fault(self, run, faults):
        """A failure of the CRL, OCSP, TSA or trusted list, while the block runs."""
        if run.dry:
            yield
            return
        run.sandbox_changes.append("faults: " + ", ".join(f"{k}={v}" for k, v in faults.items()))
        run.say("Sandbox  PUT /api/faults  " + json.dumps(faults))
        self.api("PUT", "/api/faults", faults)
        try:
            yield
        finally:
            self.api("DELETE", "/api/faults")
            run.say("Sandbox  DELETE /api/faults")

    def tsa_arguments(self, tsa):
        url, certificate = {"tsa": ("url", "tsa"), "other": ("revokedUrl", "tsa"),
                            "revoked": ("revokedUrl", "tsa-revoked"), "expired": ("expiredUrl", "tsa-expired")}[tsa]
        return ["--tsa", self.info["tsa"][url], "--tsa-cert", self.certificate_pem(certificate)]

    def _post(self, url, body):
        request = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                         headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.read()

    def log_mark(self):
        try:
            entries = self.api("GET", "/api/log?limit=1")
            entries = entries.get("entries", entries) if isinstance(entries, dict) else entries
            return max((entry.get("id", 0) for entry in entries), default=0) if entries else 0
        except (urllib.error.URLError, OSError, ValueError, AttributeError):
            return None

    def log_since(self, mark):
        if mark is None:
            return []
        try:
            entries = self.api("GET", f"/api/log?after={mark}&limit=200")
            entries = entries.get("entries", entries) if isinstance(entries, dict) else entries
            return [{key: entry.get(key) for key in ("id", "time", "service", "method", "path", "status", "summary")
                     if key in entry} for entry in entries or []]
        except (urllib.error.URLError, OSError, ValueError, AttributeError):
            return []

    # -- the command line ------------------------------------------------------------------------------------------

    def run_cli(self, arguments):
        full = self.cli_command + [str(argument) for argument in arguments] \
            + (self.network if arguments and arguments[0] in ("iofe", "sign", "inspect") else [])
        try:
            done = subprocess.run(full, capture_output=True, text=True, env=self.environment, timeout=300,
                                  encoding="utf-8", errors="replace")
        except FileNotFoundError as error:
            raise Problem(f"`{self.cli_command[0]}` was not found: install the tool (dotnet tool install --global "
                          "SimpleSign.Cli) or give --cli.") from error
        shown = " ".join(shlex.quote(part) for part in ["simplesign"] + [str(a) for a in arguments])
        return shown, done.returncode, (done.stdout + done.stderr)

    # -- keys ------------------------------------------------------------------------------------------------------

    @staticmethod
    def _find_softhsm():
        candidates = [os.environ.get("SOFTHSM2_MODULE", ""), "/opt/homebrew/lib/softhsm/libsofthsm2.so",
                      "/usr/local/lib/softhsm/libsofthsm2.so", "/usr/lib/softhsm/libsofthsm2.so",
                      "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
                      "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so", r"C:\SoftHSM2\lib\softhsm2-x64.dll"]
        return next((path for path in candidates if path and os.path.exists(path)), None)

    def has_token(self):
        return bool(self.pkcs11_library) and bool(self.environment.get("SOFTHSM2_CONF")) \
            and os.path.exists(self.environment["SOFTHSM2_CONF"])

    def pkcs11_arguments(self, signer, module=None, pin=None):
        declared = {**MODULE, **(module or {})}
        if pin:
            self.environment["AUD_WRONG_PIN"] = pin
        return ["--pkcs11-lib", self.pkcs11_library, "--pkcs11-token", TOKEN_LABEL, "--pkcs11-key", signer,
                "--pin", "env:AUD_WRONG_PIN" if pin else "env:AUD_PIN",
                "--module-manufacturer", declared["manufacturer"], "--module-model", declared["model"],
                "--module-certification", declared["certification"], "--module-certificate", declared["certificate"]]

    def credential(self, signer):
        """The remote credential of a Sandbox certificate, created the first time it is asked for."""
        if self._credentials is None:
            self._credentials = {entry["id"] for entry in self.api("GET", "/api/csc/credentials")}
        name = f"aud-{signer}"
        if name not in self._credentials:
            self.api("POST", "/api/csc/credentials", {"certificateId": signer, "credentialId": name, "scal": "1"})
            self._credentials.add(name)
        return name

    def remote_arguments(self, credential, service_name=None, pin=None):
        csc = self.info["csc"]
        if pin:
            self.environment["AUD_WRONG_PIN"] = pin
        return ["--csc-url", csc["baseUrl"], "--csc-credential", credential,
                "--csc-client-id", csc["clientId"], "--csc-client-secret", "env:AUD_CSC_SECRET",
                "--pin", "env:AUD_WRONG_PIN" if pin else "env:AUD_CSC_PIN",
                "--service-provider", SERVICE["provider"], "--service-name", service_name or self.service_name,
                "--service-accreditation", SERVICE["accreditation"], "--service-reference", SERVICE["reference"]]

    @staticmethod
    def contingency_arguments(reference, hours):
        until = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=hours)
        return ["--contingency", reference, "--contingency-until", until.strftime("%Y-%m-%dT%H:%M:%SZ")]

    # -- files -----------------------------------------------------------------------------------------------------

    def document(self, kind):
        if kind not in self._documents:
            path = self.work / {"pdf": "documento.pdf", "xml": "factura.xml", "bin": "constancia.txt"}[kind]
            if kind == "pdf":
                path.write_bytes(minimal_pdf())
            elif kind == "xml":
                path.write_text('<?xml version="1.0" encoding="UTF-8"?>\n<factura><serie>F001</serie>'
                                "<numero>123</numero><total moneda=\"PEN\">118.00</total></factura>\n", encoding="utf-8")
            else:
                path.write_text("Constancia de pago 2026-001\n", encoding="utf-8")
            self._documents[kind] = str(path)
        return self._documents[kind]

    def certificate_pem(self, certificate):
        path = self.work / f"{certificate}.pem"
        if not path.exists():
            content = self.api("GET", f"/api/certificates/{certificate}/cer", raw=True)
            if b"BEGIN CERTIFICATE" not in content:
                body = base64.encodebytes(content).decode().strip()
                content = f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n".encode()
            path.write_bytes(content)
        return str(path)

    def pfx(self, signer):
        path = self.work / f"{signer}.pfx"
        if not path.exists():
            path.write_bytes(self.api("GET", f"/api/certificates/{signer}/pfx", raw=True))
        return str(path), self.info["pfxPassword"]

    def other_root(self):
        """A root that issued none of the Sandbox's certificates: the TSA's own self-signed CA."""
        path = self.work / "otra-raiz.pem"
        if not path.exists():
            content = self.api("GET", "/aia/tsa-ca.cer", raw=True)
            body = base64.encodebytes(content).decode().strip()
            path.write_text(f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n", encoding="utf-8")
        return str(path)

    def sample(self, signer, dry=False):
        """
        A document as a third party would send it, signed with a Sandbox certificate. It is made with the general
        signer under its most permissive policy, so a revoked or weak certificate signs: the verification agent,
        not the signer, is what a verification scenario tests.
        """
        if signer not in self._samples:
            path = self.work / f"recibido-{signer}.pdf"
            pfx, password = self.pfx(signer)
            command, code, text = self.run_cli(["sign", self.document("pdf"), "--output", str(path), "--cert", pfx,
                                                "--password", password, "--signing-policy", "minimal"])
            if code != 0 or not path.exists():
                raise Problem(f"The test document of '{signer}' could not be prepared:\n$ {command}\n{text}")
            self._samples[signer] = str(path)
        return self._samples[signer]

    def expired_sample(self, dry=False):
        """A document signed with a certificate that lives a few seconds, read once it has expired."""
        if "short-lived" not in self._samples:
            pfx = self.work / "corta-vida.pfx"
            request = urllib.request.Request(self.sandbox + "/api/certificates/short-lived?seconds=4", method="POST")
            with urllib.request.urlopen(request, timeout=60) as response:
                pfx.write_bytes(response.read())
            path = self.work / "recibido-expirado.pdf"
            command, code, text = self.run_cli(["sign", self.document("pdf"), "--output", str(path), "--cert", str(pfx),
                                                "--password", self.info["pfxPassword"], "--signing-policy", "minimal"])
            if code != 0 or not path.exists():
                raise Problem(f"The test document of a short-lived certificate could not be prepared:\n$ {command}\n{text}")
            time.sleep(6)
            self._samples["short-lived"] = str(path)
        return self._samples["short-lived"]


class RealAudit(Audit):
    """
    A real environment, described by a file (entorno.ejemplo.json): the operator's cryptographic module, the
    certificates a real CA issued, INDECOPI's list. Nothing of a Sandbox is asked for. What a scenario needs and the
    environment does not have (a failure of a third party, a certificate nobody issued) is not made up: the
    scenario is reported as not run here.
    """

    real, keeps_log, setup_label = True, False, "Entorno"

    def __init__(self, options):
        super().__init__(options)
        self.file = pathlib.Path(options.entorno).expanduser().resolve()
        self.sandbox, self.config, self.name = None, {}, self.file.stem

    def _path(self, value):
        """A file of the environment: as given, or next to the environment file."""
        path = pathlib.Path(str(value)).expanduser()
        return str(path if path.is_absolute() else self.file.parent / path)

    def prepare(self):
        try:
            self.config = json.loads(self.file.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError) as error:
            raise Problem(f"The environment file {self.file} cannot be read: {error}") from error
        config = self.config
        self.name = config.get("name") or self.file.stem
        module, declared, keys = config.get("pkcs11") or {}, config.get("module") or {}, config.get("keys") or {}
        missing = [f"pkcs11.{name}" for name in ("lib", "token", "pin") if not module.get(name)] \
            + [f"module.{name}" for name in ("manufacturer", "model", "certification", "certificate") if not declared.get(name)] \
            + ([] if keys.get(DEFAULT) or keys.get(SIGNER) else [f"keys.{DEFAULT}"])
        if missing:
            raise Problem(f"{self.file} lacks: {', '.join(missing)} (see entorno.ejemplo.json).")
        pin = str(module["pin"])
        if not pin.startswith("env:"):
            raise Problem("pkcs11.pin is the name of an environment variable (env:HSM_PIN): the PIN is not written in the file.")
        if not os.environ.get(pin[4:]):
            raise Problem(f"The environment variable {pin[4:]} (pkcs11.pin) is not set.")

        files = [("pkcs11.lib", module["lib"]), ("tsa.certificate", (config.get("tsa") or {}).get("certificate")),
                 ("otherRoot", config.get("otherRoot"))]
        files += [("chain", path) for path in config.get("chain") or []]
        files += [(f"received.{name}", path) for name, path in (config.get("received") or {}).items()]
        files += [(f"trustedList.{name}", path) for name, path in (config.get("trustedList") or {}).items()]
        absent = [f"{name} ({self._path(path)})" for name, path in files if path and not os.path.exists(self._path(path))]
        if absent:
            raise Problem(f"Files named in {self.file.name} were not found: {', '.join(absent)}")

        self.work.mkdir(parents=True, exist_ok=True)
        self.info = {}
        self.pkcs11_library = self._path(module["lib"])
        self.environment["NO_COLOR"] = "1"
        # INDECOPI's own list unless the file says otherwise; and no allowance of the Sandbox's (loopback, LDAP, a
        # test root for HTTPS) unless the file asks for one, which only a rehearsal of this mode does.
        self.trust = self._arguments(config.get("trust") or [])
        self.network = self._arguments(config.get("network") or [])
        command, code, text = self.run_cli(["iofe", "--help"])
        if code != 0:
            raise Problem(f"`{command}` failed: is the IOFE extension installed? "
                          "(simplesign extension install SimpleSign.Peru.Iofe.Cli)\n" + text)

    def _arguments(self, arguments):
        """Command-line arguments from the file, with the files among them found next to it."""
        out = []
        for number, value in enumerate(arguments):
            option = arguments[number - 1] if number else ""
            is_file = option in ("--tsl-signer", "--trust-root", "--tls-trust") \
                or (option == "--tsl" and not re.match(r"https?://", str(value)))
            out.append(self._path(value) if is_file else str(value))
        return out

    # -- what a scenario may ask -------------------------------------------------------------------------------------

    def sources(self):
        return ["pkcs11"]

    def any_key(self):
        return "pkcs11"

    def has_token(self):
        return True

    def permits(self, scenario_id):
        return scenario_id in (self.config.get("allow") or [])

    def _label(self, signer):
        """The label, in the module, of the key whose certificate a scenario asks for by its role."""
        keys = self.config.get("keys") or {}
        return keys.get(signer) or (keys.get(DEFAULT) if signer == SIGNER else None)

    def has_key(self, signer):
        return bool(self._label(signer))

    def has_received(self, signer):
        return bool((self.config.get("received") or {}).get(signer))

    def sample_signer(self, signer):
        return self.signer_names.get(signer, "")

    def where(self):
        module, declared = self.config["pkcs11"], self.config["module"]
        return f"{self.name} · PKCS#11 «{module['token']}» ({declared['manufacturer']} {declared['model']})"

    def reset(self):
        pass

    def log_mark(self):
        return None

    def log_since(self, mark):
        return []

    def pkcs11_arguments(self, signer, module=None, pin=None):
        label = self._label(signer)
        if not label:
            raise Unavailable("na_key", signer)
        token, declared = self.config["pkcs11"], {**self.config["module"], **(module or {})}
        if pin:
            # A PIN that is certainly not the token's.
            actual = os.environ.get(str(token["pin"])[4:], "")
            self.environment["AUD_WRONG_PIN"] = pin if pin != actual else pin[::-1] + "0"
        arguments = ["--pkcs11-lib", self.pkcs11_library, "--pkcs11-token", token["token"], "--pkcs11-key", label,
                     "--pin", "env:AUD_WRONG_PIN" if pin else token["pin"],
                     "--module-manufacturer", declared["manufacturer"], "--module-model", declared["model"],
                     "--module-certification", declared["certification"], "--module-certificate", declared["certificate"]]
        for certificate in self.config.get("chain") or []:
            arguments += ["--chain", self._path(certificate)]
        return arguments

    def credential(self, signer):
        raise Unavailable("na_remote")

    def remote_arguments(self, credential, service_name=None, pin=None):
        raise Unavailable("na_remote")

    def tsa_arguments(self, tsa):
        if tsa in ("revoked", "expired"):
            raise Unavailable("na_fault", f"tsa={tsa}")
        authority = self.config.get("tsa") or {}
        if not authority.get("url") or not authority.get("certificate"):
            raise Unavailable("na_tsa")
        # "other": the same authority, expected to be someone else, so its token is not the expected authority's.
        certificate = self.other_root() if tsa == "other" else self._path(authority["certificate"])
        return ["--tsa", authority["url"], "--tsa-cert", certificate]

    def other_root(self):
        if not self.config.get("otherRoot"):
            raise Unavailable("na_other_root")
        return self._path(self.config["otherRoot"])

    def pfx(self, signer):
        """Any file will do: `iofe sign` has no option that would read it."""
        path = self.work / "no-es-una-clave.pfx"
        if not path.exists():
            path.write_bytes(b"No es una clave: `simplesign iofe sign` no tiene opcion que lea este archivo.\n")
        return str(path), "x"

    @contextlib.contextmanager
    def fault(self, run, faults):
        """Only the trusted list can be shown wrong here, with a copy of it; a CA or a TSA does not fail on request."""
        if set(faults) != {"trustedList"}:
            raise Unavailable("na_fault", ", ".join(f"{name}={value}" for name, value in faults.items()))
        run.trust_override, note = self._wrong_list(faults["trustedList"], run.dry)
        if not run.dry:
            run.sandbox_changes.append(note)
            run.say(f"{self.setup_label}  {note}")
        try:
            yield
        finally:
            run.trust_override = None

    def _wrong_list(self, kind, dry):
        """The trust arguments that give the agent a list that is wrong in one way, and what was done."""
        if "--trust-root" in self.trust:
            raise Unavailable("na_roots")
        given = dict(zip(self.trust[::2], self.trust[1::2]))
        url, signer = given.get("--tsl"), given.get("--tsl-signer")
        signer_arguments = ["--tsl-signer", signer] if signer else []
        copies = self.config.get("trustedList") or {}
        if kind == "WrongSigner":
            return (["--tsl", url] if url else []) + ["--tsl-signer", self.other_root()], \
                "la lista de confianza, con otro certificado como el de su firmante (--tsl-signer)"
        if kind == "Tampered":
            path = self.work / "tsl-alterada.xml"
            if not dry and not path.exists():
                path.write_bytes(self._tampered(self._list(url, copies.get("copy"))))
            return ["--tsl", str(path)] + signer_arguments, \
                f"copia de la lista de confianza ({url or INDECOPI_LIST}) con un valor alterado después de firmada"
        if kind == "Expired":
            if not copies.get("expired"):
                raise Unavailable("na_list_copy", "Expired (trustedList.expired)")
            return ["--tsl", self._path(copies["expired"])] + signer_arguments, \
                f"copia vencida de la lista de confianza ({os.path.basename(copies['expired'])})"
        raise Unavailable("na_fault", f"trustedList={kind}")

    def _list(self, url, copy):
        """The trusted list as published: the copy the file names, or downloaded."""
        source = self._path(copy) if copy else (url or INDECOPI_LIST)
        if not re.match(r"https?://", source):
            return pathlib.Path(source).read_bytes()
        try:
            with urllib.request.urlopen(source, timeout=60) as response:
                return response.read()
        except (urllib.error.URLError, OSError) as error:
            raise Problem(f"The trusted list could not be downloaded from {source} ({error}); give a copy of it in "
                          "trustedList.copy.") from error

    @staticmethod
    def _tampered(data):
        """The list with one signed value changed: its sequence number, or failing that the first name in it."""
        changed, count = re.subn(rb"(<(?:\w+:)?TSLSequenceNumber>\s*)(\d+)",
                                 lambda found: found.group(1) + str(int(found.group(2)) + 1).encode(), data, count=1)
        if not count:
            changed, count = re.subn(rb"(<(?:\w+:)?Name\b[^>]*>)([^<])", lambda found: found.group(1) + b"X" + found.group(2),
                                     data, count=1)
        if not count:
            raise Problem("The trusted list has neither a sequence number nor a name to change.")
        return changed

    def sample(self, signer, dry=False):
        """
        A received document: the one the file gives for that certificate, or, for the organization's own
        certificate, one the signing agent signs now. A document of a revoked or expired certificate cannot be made
        here: it has to have been signed while the certificate was good.
        """
        received = (self.config.get("received") or {}).get(signer)
        if received:
            return self._path(received)
        if signer != SIGNER:
            raise Unavailable("na_received", signer)
        path = self.work / "recibido-propio.pdf"
        if dry:
            self.pkcs11_arguments(signer)
            return str(path)
        if signer not in self._samples:
            arguments = ["iofe", "sign", self.document("pdf"), "--output", str(path), "--transaction", "auditoria/muestra",
                         "--allow", "auditoria", "--audit-log", str(self.work / "auditoria-de-muestras.jsonl")] \
                + self.trust + self.pkcs11_arguments(signer)
            command, code, text = self.run_cli(arguments)
            (self.work / "recibido-propio.txt").write_text(f"$ {command}\n{text.rstrip()}\n[exit {code}]\n", encoding="utf-8")
            if code != 0 or not path.exists():
                raise Problem(f"The document to verify could not be signed:\n$ {command}\n{text}")
            self.signer_names.setdefault(signer, signer_in(text))
            self._samples[signer] = str(path)
        return self._samples[signer]

    def expired_sample(self, dry=False):
        received = (self.config.get("received") or {}).get("expired")
        if not received:
            raise Unavailable("na_received", "expired")
        return self._path(received)

    def describe(self):
        """
        What the audit report records about the environment (annex B): the tool and its extensions, and the module
        with the certificates in it — subject, validity and thumbprint of each.
        """
        folder = self.out / "00-entorno"
        folder.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.file, folder / "entorno.json")
        kept = []
        for name, arguments in (("version", ["version"]), ("extensiones", ["extension", "list"]),
                                ("modulo-y-certificados", ["pkcs11", "list", "--lib", self.pkcs11_library])):
            command, code, text = self.run_cli(arguments)
            (folder / f"{name}.txt").write_text(f"$ {command}\n{text.rstrip()}\n[exit {code}]\n", encoding="utf-8")
            kept.append({"file": f"00-entorno/{name}.txt", "command": command, "exit": code, "text": text})
        return kept

    def profile(self, signed):
        """The certificate of a signature this run made, as `inspect` shows it: the profile annex B asks to attach."""
        command, code, text = self.run_cli(["inspect", signed])
        path = self.out / "00-entorno" / "certificado-de-firma.txt"
        path.write_text(f"$ {command}\n{text.rstrip()}\n[exit {code}]\n", encoding="utf-8")
        return {"file": "00-entorno/certificado-de-firma.txt", "command": command, "exit": code, "text": text}


def minimal_pdf() -> bytes:
    """A one-page PDF with a line of text."""
    stream = b"BT /F1 14 Tf 72 760 Td (Factura F001-123 - documento de prueba) Tj ET"
    objects = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
               b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R "
               b"/Resources << /Font << /F1 5 0 R >> >> >>",
               b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
               b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    out, offsets = b"%PDF-1.7\n", []
    for number, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    out += b"".join(b"%010d 00000 n \n" % offset for offset in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref)
    return out


# ── Reports ──────────────────────────────────────────────────────────────────────────────────────────────────────

def all_items():
    return [f"F-{n}" for n in range(1, 33)] + [f"V-{n}" for n in range(1, 33)] + [f"S-{n}" for n in range(1, 5)]


def status(run, lang):
    if run.get("unavailable"):
        return tr("not_here", lang)
    return tr("skipped", lang) if run.get("skipped") else tr("passed" if run["passed"] else "failed", lang)


def capital(text):
    return text[:1].upper() + text[1:]


def not_run(run):
    """Whether a scenario was left out: by the choice of key source, or because the environment cannot show it."""
    return bool(run.get("skipped") or run.get("unavailable"))


def why(run, lang):
    """Why a scenario was not run, and what its rehearsal in a Sandbox showed, when one was given."""
    reason = phrase(run["unavailable"], lang) if run.get("unavailable") else str(run.get("skipped") or "")
    rehearsal = run.get("rehearsal")
    if rehearsal:
        reason += f" — {tr('rehearsal', lang)}: {tr('passed' if rehearsal['passed'] else 'failed', lang)}, `{rehearsal['folder']}/`"
    return reason


def item_outcome(of_item, lang):
    """
    An item's result and its class: by what ran here; failing that, by the rehearsal of what could not run here,
    said to be a rehearsal.
    """
    ran = [r for r in of_item if not not_run(r)]
    if ran:
        ok = all(r["passed"] for r in ran)
        return tr("passed" if ok else "failed", lang), "ok" if ok else "bad"
    rehearsed = [r["rehearsal"] for r in of_item if r.get("rehearsal")]
    if rehearsed:
        ok = all(r["passed"] for r in rehearsed)
        return f"{tr('passed' if ok else 'failed', lang)} ({tr('rehearsal', lang)})", "none"
    return "—", "none"


def summary_line(results, lang):
    done = [r for r in results if not not_run(r)]
    line = (f"{tr('passed', lang)}: {sum(1 for r in done if r['passed'])} · "
            f"{tr('failed', lang)}: {sum(1 for r in done if not r['passed'])} · "
            f"{tr('skipped', lang)}: {sum(1 for r in results if r.get('skipped'))}")
    away = sum(1 for r in results if r.get("unavailable"))
    return line + (f" · {tr('not_here', lang)}: {away}" if away else "")


def introduction(env, lang):
    if not env.get("real"):
        return tr("intro", lang)
    return tr("intro_real", lang) + (" " + tr("intro_rehearsal", lang) if env.get("rehearsal") else "")


def report_markdown(results, env, lang):
    lines = [f"# {tr('title', lang)}", "", introduction(env, lang), "",
             f"- {tr('generated', lang)}: {env['time']}",
             f"- {tr('environment', lang)}: {env['cli']} · {env['where']} · {env['platform']}", ""]
    if env.get("rehearsal"):
        lines[-1:] = [f"- {capital(tr('rehearsal', lang))}: {env['rehearsal']}", ""]
    if env.get("files"):
        lines += [f"## {tr('environment_files', lang)}", ""]
        for kept in env["files"]:
            lines += [f"`{kept['file']}`", "", "```", "$ " + kept["command"], kept["text"].rstrip(), f"[exit {kept['exit']}]", "```", ""]
    lines += [f"## {tr('summary', lang)}", "", summary_line(results, lang), "",
              f"## {tr('by_item', lang)}", "",
              f"| {tr('item', lang)} | {tr('asks', lang)} | {tr('scenarios', lang)} | {tr('result', lang)} |",
              "|---|---|---|---|"]
    for item in all_items():
        of_item = [r for r in results if item in r["items"]]
        if not of_item and not item_text(item, lang):
            continue
        names = ", ".join(sorted({r["id"] for r in of_item})) or f"_{tr('no_scenario', lang)}_"
        lines.append(f"| {item} | {item_text(item, lang)} | {names} | {item_outcome(of_item, lang)[0]} |")
    lines += ["", f"## {tr('scenarios', lang)}", ""]
    for r in results:
        key = tr("key_" + (r["key"] or "none"), lang)
        lines += [f"### {r['folder']} — {r['title'][lang]}", "",
                  f"{tr('item', lang)}: {', '.join(r['items'])} · {tr('key', lang)}: {key} · "
                  f"**{status(r, lang)}**" + (f" ({why(r, lang)})" if not_run(r) else ""), ""]
        if not_run(r):
            continue
        for change in r["sandbox"]:
            lines.append(f"- {tr('setup' if env.get('real') else 'sandbox', lang)}: `{change}`")
        for step in r["steps"]:
            lines += ["", "```", "$ " + step["command"], step["text"].rstrip(), f"[exit {step['exit']}]", "```", ""]
            for check in step["checks"]:
                lines.append(f"- {'✓' if check['ok'] else '✗'} {tr('expected', lang)}: {phrase(check['expected'], lang)}"
                             + ("" if check["ok"] else f" — {tr('found', lang)}: {phrase(check['found'], lang)}"))
        for check in r["checks"]:
            lines.append(f"- {'✓' if check['ok'] else '✗'} {tr('expected', lang)}: {phrase(check['expected'], lang)} — "
                         f"{tr('found', lang)}: {phrase(check['found'], lang)}")
        if r.get("error"):
            lines.append(f"- ✗ {r['error']}")
        lines += ["", f"{tr('evidence', lang)}: `{r['folder']}/`", ""]
    return "\n".join(lines) + "\n"


def report_html(results, env, lang):
    e = html.escape
    rows = []
    for item in all_items():
        of_item = [r for r in results if item in r["items"]]
        if not of_item and not item_text(item, lang):
            continue
        outcome, css = item_outcome(of_item, lang)
        names = ", ".join(f'<a href="#{e(r["folder"])}">{e(r["id"])}</a>' for r in of_item) \
            or f"<em>{e(tr('no_scenario', lang))}</em>"
        rows.append(f'<tr><td>{item}</td><td>{e(item_text(item, lang))}</td><td>{names}</td>'
                    f'<td class="{css}">{e(outcome)}</td></tr>')
    sections = []
    for r in results:
        css = "none" if not_run(r) else ("ok" if r["passed"] else "bad")
        body = [f'<section id="{e(r["folder"])}"><h3>{e(r["folder"])} — {e(r["title"][lang])} '
                f'<span class="{css}">{e(status(r, lang))}</span></h3>',
                f'<p>{e(tr("item", lang))}: {e(", ".join(r["items"]))} · {e(tr("key", lang))}: '
                f'{e(tr("key_" + (r["key"] or "none"), lang))}'
                + (f' · {e(why(r, lang)).replace("`", "")}' if not_run(r) else "") + "</p>"]
        if not not_run(r):
            for change in r["sandbox"]:
                body.append(f'<p>{e(tr("setup" if env.get("real") else "sandbox", lang))}: <code>{e(change)}</code></p>')
            for step in r["steps"]:
                body.append(f'<pre>$ {e(step["command"])}\n{e(step["text"].rstrip())}\n[exit {step["exit"]}]</pre><ul>')
                for check in step["checks"]:
                    body.append(f'<li class="{"ok" if check["ok"] else "bad"}">{e(tr("expected", lang))}: '
                                f'{e(phrase(check["expected"], lang))}'
                                + ("" if check["ok"] else f' — {e(tr("found", lang))}: {e(phrase(check["found"], lang))}')
                                + "</li>")
                body.append("</ul>")
            if r["checks"]:
                body.append("<ul>")
                for check in r["checks"]:
                    body.append(f'<li class="{"ok" if check["ok"] else "bad"}">{e(tr("expected", lang))}: '
                                f'{e(phrase(check["expected"], lang))} — {e(tr("found", lang))}: '
                                f'{e(phrase(check["found"], lang))}</li>')
                body.append("</ul>")
            if r.get("error"):
                body.append(f'<p class="bad">{e(r["error"])}</p>')
            body.append(f'<p>{e(tr("evidence", lang))}: <code>{e(r["folder"])}/</code></p>')
        sections.append("\n".join(body) + "</section>")
    rehearsal = f"<p>{e(capital(tr('rehearsal', lang)))}: {e(env['rehearsal'])}</p>\n" if env.get("rehearsal") else ""
    files = "" if not env.get("files") else f"<h2>{e(tr('environment_files', lang))}</h2>\n" + "\n".join(
        f'<p><code>{e(kept["file"])}</code></p><pre>$ {e(kept["command"])}\n{e(kept["text"].rstrip())}\n[exit {kept["exit"]}]</pre>'
        for kept in env["files"]) + "\n"
    return f"""<!doctype html>
<html lang="{lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(tr('title', lang))}</title>
<style>
body {{ font: 15px/1.5 system-ui, sans-serif; margin: 2rem auto; max-width: 70rem; padding: 0 1rem; color: #1b1f23; }}
table {{ border-collapse: collapse; width: 100%; }} td, th {{ border: 1px solid #d0d7de; padding: .35rem .6rem; text-align: left; vertical-align: top; }}
pre {{ background: #f6f8fa; padding: .8rem; overflow-x: auto; font-size: 13px; }} code {{ background: #f6f8fa; padding: 0 .25rem; }}
.ok {{ color: #1a7f37; font-weight: 600; }} .bad {{ color: #cf222e; font-weight: 600; }} .none {{ color: #6e7781; }}
li.ok, li.bad {{ font-weight: 400; }} section {{ border-top: 1px solid #d0d7de; margin-top: 1.5rem; }}
</style></head><body>
<h1>{e(tr('title', lang))}</h1>
<p>{e(introduction(env, lang)).replace('`', '')}</p>
<p>{e(tr('generated', lang))}: {e(env['time'])} · {e(tr('environment', lang))}: {e(env['cli'])} · {e(env['where'])} · {e(env['platform'])}</p>
{rehearsal}{files}<h2>{e(tr('summary', lang))}</h2>
<p>{e(summary_line(results, lang))}</p>
<h2>{e(tr('by_item', lang))}</h2>
<table><tr><th>{e(tr('item', lang))}</th><th>{e(tr('asks', lang))}</th><th>{e(tr('scenarios', lang))}</th><th>{e(tr('result', lang))}</th></tr>
{chr(10).join(rows)}</table>
<h2>{e(tr('scenarios', lang))}</h2>
{chr(10).join(sections)}
</body></html>
"""


def write_catalog():
    catalog = {"description": "The scenarios of auditoria.py, by item of annex B. Written by auditoria.py --write-catalog; "
                              "AnnexBCoverageTests checks it against indecopi-checklist.md.",
               "scenarios": [{"id": s.id, "items": s.items, "keys": s.keys, "title": s.titles} for s in SCENARIOS]}
    CATALOG.write_text(json.dumps(catalog, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{CATALOG}: {len(SCENARIOS)} scenarios, {len({i for s in SCENARIOS for i in s.items})} items")


# ── Main ─────────────────────────────────────────────────────────────────────────────────────────────────────────

def unavailable(env, scn, key):
    """
    Why the environment cannot show a scenario, or None when it can. The scenario is gone through without a command
    being run, so that nothing is signed for a scenario that would stop halfway for lack of something.
    """
    if not env.real:
        return None
    try:
        scn.run(Run(env, scn, key, 0, dry=True))
    except Unavailable as missing:
        return missing.reason
    except Exception:  # whatever else it trips on, the run itself will say
        return None
    return None


def rehearsed(folder):
    """The results of a run in a Sandbox, by scenario: what stands in for what this environment cannot show."""
    if not folder:
        return {}, None
    path = pathlib.Path(folder).expanduser()
    path = path / "resultados.json" if path.is_dir() else path
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise Problem(f"The rehearsal's results cannot be read from {path}: {error}") from error
    found = {}
    for result in data.get("results", []):
        if not result.get("skipped") and not result.get("unavailable"):
            found.setdefault(result["id"], []).append(result)
    where = (data.get("environment") or {})
    return found, f"{where.get('where') or 'Sandbox ' + str(where.get('sandbox', ''))} · {where.get('time', '')} · {path.parent}"


def write_manifest(out):
    """The SHA-256 of every file of the evidence, so that a copy of it can be told from the original."""
    lines = []
    for path in sorted(item for item in out.rglob("*") if item.is_file() and item.name != "MANIFIESTO.sha256"):
        lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(out).as_posix()}")
    (out / "MANIFIESTO.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sandbox", default=os.environ.get("SANDBOX_URL", "http://localhost:5300"), help="the running Sandbox")
    parser.add_argument("--entorno", metavar="FILE", help="a real environment instead of the Sandbox, described by this file "
                        "(entorno.ejemplo.json): the module, its keys, the time-stamp authority")
    parser.add_argument("--ensayo", metavar="FOLDER", help="with --entorno: the evidence of a run in a Sandbox, named in the "
                        "report for what the real environment cannot show")
    parser.add_argument("--cli", default="simplesign", help='the command line with the IOFE extension (default: "simplesign")')
    parser.add_argument("--key", choices=("remote", "pkcs11", "both"), default="remote",
                        help="where the signing key is, in a Sandbox (a real environment says it in its file)")
    parser.add_argument("--pkcs11-lib", help="the PKCS#11 library of the token (default: SoftHSM2, where it is found)")
    parser.add_argument("--out", default="evidencias", help="the folder of the evidence (default: ./evidencias)")
    parser.add_argument("--lang", choices=LANGS, default="en", help="the language of what is printed (the report is written in both)")
    parser.add_argument("--item", action="append", default=[], help="only the scenarios of this item of annex B (F-8); repeatable")
    parser.add_argument("--scenario", action="append", default=[], help="only this scenario; repeatable")
    parser.add_argument("--list", action="store_true", help="list the scenarios and stop; with --entorno, which of them it can show")
    parser.add_argument("--write-catalog", action="store_true", help="write escenarios.json and stop")
    parser.add_argument("-v", "--verbose", action="store_true", help="print every command and its output")
    options = parser.parse_args()
    options.live = bool(options.item or options.scenario)
    lang = options.lang

    if options.write_catalog:
        write_catalog()
        return 0
    chosen = [s for s in SCENARIOS
              if (not options.item or set(i.upper() for i in options.item) & set(s.items))
              and (not options.scenario or s.id in options.scenario)]
    if options.list and not options.entorno:
        for s in chosen:
            print(f"{s.id:32} {','.join(s.items):24} {s.keys:8} {s.titles[lang]}")
        return 0
    if not chosen:
        print("No scenario matches.", file=sys.stderr)
        return 2

    env = RealAudit(options) if options.entorno else Audit(options)
    try:
        env.prepare()
        rehearsal, rehearsal_name = rehearsed(options.ensayo if env.real else None)
    except Problem as problem:
        print(f"✗ {problem}", file=sys.stderr)
        return 2
    sources = env.sources()

    planned = []
    for scn in chosen:
        keys = sources if scn.keys == "signing" else [scn.keys] if scn.keys in ("pkcs11", "remote") else [None]
        planned += [(scn, key, unavailable(env, scn, key)) for key in keys]
    if options.list:
        for scn, key, reason in planned:
            state = tr("runs", lang) if reason is None else f"{tr('not_here', lang).lower()}: {phrase(reason, lang)}"
            print(f"{scn.id:32} {','.join(scn.items):24} {state}")
        can = sum(1 for _, _, reason in planned if reason is None)
        print(f"\n{tr('runs', lang)}: {can} · {tr('not_here', lang).lower()}: {len(planned) - can}")
        return 0

    files = env.describe()
    results, number = [], 0
    for scn, key, reason in planned:
        number += 1
        run = Run(env, scn, key, number, dry=reason is not None)
        record = {"id": scn.id, "items": scn.items, "title": scn.titles, "key": key, "folder": run.folder.name}
        label = f"[{number:02d}] {scn.id}" + (f" ({key})" if key else "")
        if reason is not None:
            before = next((r for r in rehearsal.get(scn.id, []) if r.get("key") == key), None) \
                or next(iter(rehearsal.get(scn.id, [])), None)
            if before:
                record["rehearsal"] = {"passed": before["passed"], "folder": before["folder"], "key": before.get("key")}
            print(f"– {label}: {tr('not_here', lang).lower()} ({phrase(reason, lang)})")
            results.append({**record, "unavailable": reason, "passed": False})
            continue
        skipped = None
        if key == "pkcs11" and (scn.keys == "pkcs11" or "pkcs11" in sources) and not env.has_token():
            skipped = tr("no_token", lang)
        elif key in ("pkcs11", "remote") and key not in sources:
            skipped = f"--key {key}"
        if skipped:
            print(f"– {label}: {tr('skipped', lang)} ({skipped})")
            shutil.rmtree(run.folder, ignore_errors=True)
            results.append({**record, "skipped": skipped, "passed": False})
            continue
        if options.live or options.verbose:
            print(f"\n▶ {label} — {scn.titles[lang]}  [{', '.join(scn.items)}]")
        try:
            scn.run(run)
        except Unavailable as missing:  # the dry pass should have said so
            run.error = phrase(missing.reason, lang)
        except Problem as problem:
            run.error = str(problem)
        except Exception as error:  # a scenario that breaks is a failed scenario, not a failed run
            run.error = f"{type(error).__name__}: {error}"
        finally:
            with contextlib.suppress(Exception):
                env.reset()
        run.save()
        mark = "✓" if run.passed else "✗"
        print(f"{mark} {label}: {tr('passed' if run.passed else 'failed', lang)}"
              + (f" — {run.error}" if run.error else ""))
        if not run.passed and not (options.live or options.verbose):
            for check in run.checks:
                if not check.ok:
                    print(f"     {tr('expected', lang)}: {phrase(check.expected, lang)} · "
                          f"{tr('found', lang)}: {phrase(check.found, lang)}")
        results.append({**record, "passed": run.passed, "error": run.error, "sandbox": run.sandbox_changes,
                        "steps": [{"command": s.command, "exit": s.exit, "text": s.text, "output": s.output,
                                   "checks": [vars(c) for c in s.checks]} for s in run.steps],
                        "checks": [vars(c) for c in run.extra_checks]})

    command, _, version = env.run_cli(["version"])
    meta = {"time": datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z"),
            "cli": " ".join(version.split()) or command, "where": env.where(), "real": env.real,
            "platform": f"{sys.platform}, Python {sys.version.split()[0]}"}
    if env.real:
        # The certificate that signed, as the first signature made here carries it.
        signed = next((step["output"] for r in results for step in r.get("steps", [])
                       if step.get("output") and step["exit"] == 0 and os.path.exists(step["output"])), None)
        meta["files"] = files + ([env.profile(signed)] if signed else [])
        meta["rehearsal"] = rehearsal_name
    else:
        meta["sandbox"] = f"{env.sandbox} ({env.info.get('version', '')})"
    (env.out / "resultados.json").write_text(json.dumps({"environment": meta, "results": results}, indent=1,
                                                         ensure_ascii=False), encoding="utf-8")
    for language in LANGS:
        (env.out / f"informe.{language}.md").write_text(report_markdown(results, meta, language), encoding="utf-8")
        (env.out / f"informe.{language}.html").write_text(report_html(results, meta, language), encoding="utf-8")
    write_manifest(env.out)

    failed = [r for r in results if not not_run(r) and not r["passed"]]
    print("\n" + summary_line(results, lang))
    print(f"{tr('evidence', lang)}: {env.out}{os.sep}informe.{lang}.html")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
