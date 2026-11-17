#!/usr/bin/env python3
"""The accreditation audit, run: INDECOPI's guide v4.0, annex B, shown by the accredited configuration itself.

Every scenario prepares a running SimpleSign Sandbox through its API (a failure of the CRL, OCSP, TSA or trusted
list, a revocation, a credential), runs `simplesign iofe sign|verify|view` — the commands of
SimpleSign.Peru.Iofe.Accredited, not the general signers — and checks what came out: the signature, or the refusal
and its reason. What it ran, what it printed, the audit records and the files are kept as evidence, with a report
in Spanish, English and Portuguese.

    python3 auditoria.py                       every scenario, key in the Sandbox's remote signing service
    python3 auditoria.py --key both            also with the key in a PKCS#11 token (SoftHSM2)
    python3 auditoria.py --item F-8            the scenarios of one item of annex B, shown step by step
    python3 auditoria.py --scenario revocado   one scenario
    python3 auditoria.py --list                what there is to run
    python3 auditoria.py --write-catalog       writes escenarios.json (checked against the checklist by the tests)

Needs: Python 3.9+, a running Sandbox (--sandbox, default http://localhost:5300), and `simplesign` with the IOFE
extension installed (--cli, default "simplesign"). For --key pkcs11: a token filled by
tools/stack/softhsm-provision.sh and SOFTHSM2_CONF pointing to it.

The Sandbox is a test PKI: nothing here proves what only the real environment can (the HSM's certification, the
provider's accreditation, INDECOPI's own list). docs/roteiro-de-auditoria.md says what changes on the audit day.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import datetime
import html
import json
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
CATALOG = HERE / "escenarios.json"
LANGS = ("es", "en", "pt")

# What the Sandbox publishes about itself; a real deployment declares its own module or service.
MODULE = {"manufacturer": "SoftHSM project", "model": "SoftHSM v2",
          "certification": "ninguna (token de software para pruebas)", "certificate": "n/a"}
SERVICE = {"provider": "SimpleSign Sandbox", "accreditation": "ninguna (servicio de pruebas)", "reference": "n/a"}
TOKEN_LABEL = "SimpleSign Sandbox"
SENDER = "20123456789"

TEXT = {
    "title": {"es": "Auditoría de acreditación — Guía INDECOPI v4.0, Anexo B",
              "en": "Accreditation audit — INDECOPI guide v4.0, annex B",
              "pt": "Auditoria de acreditação — Guia INDECOPI v4.0, Anexo B"},
    "intro": {
        "es": "Cada escenario fue ejecutado por la configuración acreditada (`simplesign iofe`, paquete "
              "SimpleSign.Peru.Iofe.Accredited) contra un SimpleSign Sandbox, una PKI de pruebas. Los documentos que "
              "el agente de verificación recibe se prepararon con herramientas de prueba: quien los juzga es el agente.",
        "en": "Every scenario was run by the accredited configuration (`simplesign iofe`, package "
              "SimpleSign.Peru.Iofe.Accredited) against a SimpleSign Sandbox, a test PKI. The documents the "
              "verification agent receives were prepared with test tools: the agent is what judges them.",
        "pt": "Cada cenário foi executado pela configuração acreditada (`simplesign iofe`, pacote "
              "SimpleSign.Peru.Iofe.Accredited) contra um SimpleSign Sandbox, uma PKI de testes. Os documentos que o "
              "agente de verificação recebe foram preparados com ferramentas de teste: quem os julga é o agente."},
    "passed": {"es": "CONFORME", "en": "PASSED", "pt": "CONFORME"},
    "failed": {"es": "NO CONFORME", "en": "FAILED", "pt": "NÃO CONFORME"},
    "skipped": {"es": "OMITIDO", "en": "SKIPPED", "pt": "OMITIDO"},
    "summary": {"es": "Resumen", "en": "Summary", "pt": "Resumo"},
    "by_item": {"es": "Por ítem del Anexo B", "en": "By item of annex B", "pt": "Por item do Anexo B"},
    "scenarios": {"es": "Escenarios", "en": "Scenarios", "pt": "Cenários"},
    "item": {"es": "Ítem", "en": "Item", "pt": "Item"},
    "asks": {"es": "Lo que pide la Guía", "en": "What the guide asks", "pt": "O que o guia pede"},
    "scenario": {"es": "Escenario", "en": "Scenario", "pt": "Cenário"},
    "key": {"es": "Clave", "en": "Key", "pt": "Chave"},
    "result": {"es": "Resultado", "en": "Result", "pt": "Resultado"},
    "expected": {"es": "Esperado", "en": "Expected", "pt": "Esperado"},
    "found": {"es": "Obtenido", "en": "Found", "pt": "Obtido"},
    "command": {"es": "Comando", "en": "Command", "pt": "Comando"},
    "output": {"es": "Salida", "en": "Output", "pt": "Saída"},
    "sandbox": {"es": "Preparación del Sandbox", "en": "Sandbox set-up", "pt": "Preparação do Sandbox"},
    "evidence": {"es": "Evidencia", "en": "Evidence", "pt": "Evidência"},
    "no_scenario": {"es": "sin escenario: ver la lista de verificación", "en": "no scenario: see the checklist",
                    "pt": "sem cenário: ver o checklist"},
    "environment": {"es": "Entorno", "en": "Environment", "pt": "Ambiente"},
    "generated": {"es": "Generado", "en": "Generated", "pt": "Gerado"},
    "key_remote": {"es": "servicio de firma remota", "en": "remote signing service", "pt": "serviço de assinatura remota"},
    "key_pkcs11": {"es": "módulo PKCS#11", "en": "PKCS#11 module", "pt": "módulo PKCS#11"},
    "key_none": {"es": "—", "en": "—", "pt": "—"},
    "no_token": {"es": "sin token PKCS#11 (SOFTHSM2_CONF y tools/stack/softhsm-provision.sh)",
                 "en": "no PKCS#11 token (SOFTHSM2_CONF and tools/stack/softhsm-provision.sh)",
                 "pt": "sem token PKCS#11 (SOFTHSM2_CONF e tools/stack/softhsm-provision.sh)"},
    "exp_signed": {"es": "la firma se realiza", "en": "the signature is made", "pt": "a assinatura é feita"},
    "exp_refused": {"es": "se rechaza y nada se firma", "en": "it is refused and nothing is signed",
                    "pt": "é recusado e nada é assinado"},
    "exp_accepted": {"es": "el documento se acepta", "en": "the document is accepted", "pt": "o documento é aceito"},
    "exp_rejected": {"es": "el documento se rechaza, con comunicado al emisor",
                     "en": "the document is rejected, with a notice to its sender",
                     "pt": "o documento é rejeitado, com comunicado ao remetente"},
    "exp_fails": {"es": "el comando falla", "en": "the command fails", "pt": "o comando falha"},
    "exp_ok": {"es": "el comando termina bien", "en": "the command succeeds", "pt": "o comando termina bem"},
    "exp_text": {"es": "la salida contiene", "en": "the output has", "pt": "a saída contém"},
    "exp_no_file": {"es": "no se escribe el archivo", "en": "no file is written", "pt": "nenhum arquivo é escrito"},
    "exp_file": {"es": "se escribe el archivo", "en": "the file is written", "pt": "o arquivo é escrito"},
    "exp_audit": {"es": "el registro de auditoría", "en": "the audit record", "pt": "o registro de auditoria"},
    "yes": {"es": "sí", "en": "yes", "pt": "sim"},
    "no": {"es": "no", "en": "no", "pt": "não"},
}

# What annex B asks, by the number of the item in sections 4.2 (F) and 4.3 (V), which repeat each other, and 4.4 (S).
ITEMS = {
    "1": ("Lista de confianza (TSL): verificar la firma de la AAC y que corresponde a su raíz",
          "Trusted list (TSL): check the AAC's signature and that it chains to its root",
          "Lista de confiança (TSL): verificar a assinatura da AAC e que corresponde à sua raiz"),
    "2": ("TSL: verificar que su vigencia no ha expirado", "TSL: check that it has not expired",
          "TSL: verificar que sua vigência não expirou"),
    "3": ("TSL: la EC raíz del certificado figura en la lista", "TSL: the certificate's root CA is listed",
          "TSL: a AC raiz do certificado consta na lista"),
    "4": ("TSL: descarga periódica conforme a su vigencia", "TSL: downloaded again according to its validity",
          "TSL: baixada de novo conforme sua vigência"),
    "5": ("Consulta de CRL por HTTP, LDAP o HTTPS", "CRL fetched over HTTP, LDAP or HTTPS",
          "Consulta de CRL por HTTP, LDAP ou HTTPS"),
    "6": ("La CRL está firmada por la EC autorizada", "The CRL is signed by the CA entitled to issue it",
          "A CRL é assinada pela AC autorizada"),
    "7": ("La CRL está vigente", "The CRL is current", "A CRL está vigente"),
    "8": ("La CRL se verifica antes de firmar: un certificado revocado no firma",
          "The CRL is checked before signing: a revoked certificate never signs",
          "A CRL é verificada antes de assinar: certificado revogado não assina"),
    "9": ("Ningún certificado de la cadena está revocado", "No certificate of the chain is revoked",
          "Nenhum certificado da cadeia está revogado"),
    "10": ("O consulta OCSP (RFC 2560) del certificado y su cadena", "Or OCSP (RFC 2560) for the certificate and its chain",
           "Ou consulta OCSP (RFC 2560) do certificado e da cadeia"),
    "11": ("El certificado y su cadena no han expirado", "The certificate and its chain have not expired",
           "O certificado e sua cadeia não expiraram"),
    "12": ("Se verifica el bit nonRepudiation del certificado", "The certificate's nonRepudiation bit is checked",
           "O bit nonRepudiation do certificado é verificado"),
    "13": ("Protección contra accesos no autorizados", "Protection against unauthorized access",
           "Proteção contra acessos não autorizados"),
    "14": ("Las verificaciones no pueden desactivarse (salvo contingencia aprobada por el INDECOPI)",
           "The checks cannot be switched off (except under a contingency INDECOPI approved)",
           "As verificações não podem ser desligadas (salvo contingência aprovada pelo INDECOPI)"),
    "15": ("Registros de auditoría de las firmas, por tipo de transacción",
           "Audit log of the signatures, by kind of transaction",
           "Registros de auditoria das assinaturas, por tipo de transação"),
    "16": ("Sin firmas fuera de la transacción definida", "No signatures outside the defined transaction",
           "Sem assinaturas fora da transação definida"),
    "17": ("La clave privada opera solo dentro del módulo criptográfico certificado",
           "The private key works only inside the certified cryptographic module",
           "A chave privada opera só dentro do módulo criptográfico certificado"),
    "18": ("Sin copias automáticas de la clave privada", "No automatic copies of the private key",
           "Sem cópias automáticas da chave privada"),
    "19": ("El módulo criptográfico de la solución es FIPS 140-2 o Common Criteria EAL 4+",
           "The solution's cryptographic module is FIPS 140-2 or Common Criteria EAL 4+",
           "O módulo criptográfico da solução é FIPS 140-2 ou Common Criteria EAL 4+"),
    "28": ("Algoritmos vigentes, no obsoletos", "Current, unbroken algorithms", "Algoritmos vigentes, não obsoletos"),
    "29": ("La aplicación está firmada con un certificado de firma de código",
           "The application is signed with a code-signing certificate",
           "A aplicação é assinada com certificado de assinatura de código"),
    "30": ("Visor: integridad, fecha y hora, clave pública y datos del certificado",
           "Viewer: integrity, signing time, public key and certificate data",
           "Visor: integridade, data e hora, chave pública e dados do certificado"),
    "31": ("Fecha y hora y claves públicas de la cadena, adjuntas y firmadas (datos de validación)",
           "Signing time and the chain's public keys, attached and signed (validation data)",
           "Data e hora e chaves públicas da cadeia, anexadas e assinadas (dados de validação)"),
    "32": ("Manuales de administración y de usuario", "Administrator and user manuals",
           "Manuais de administração e de usuário"),
    "S-1": ("El sello lleva el identificador del certificado de la TSA consultada",
            "The token carries the identifier of the certificate of the TSA asked",
            "O carimbo traz o identificador do certificado da TSA consultada"),
    "S-2": ("La firma del sello de tiempo verifica", "The token's signature verifies",
            "A assinatura do carimbo de tempo verifica"),
    "S-3": ("El certificado de la TSA no está revocado", "The TSA's certificate is not revoked",
            "O certificado da TSA não está revogado"),
    "S-4": ("El certificado de la TSA no ha expirado", "The TSA's certificate has not expired",
            "O certificado da TSA não expirou"),
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


def scenario(sid: str, items: list[str], keys: str, es: str, en: str, pt: str):
    """Registers a scenario. keys: 'signing' (once per key source asked for), 'pkcs11', 'remote', or 'none'."""
    def register(function):
        SCENARIOS.append(Scenario(sid, items, keys, (es, en, pt), function))
        return function
    return register


# -- 4.2 Signing: the trusted list ---------------------------------------------------------------------------------

@scenario("tsl-vigente", ["F-1", "F-3"], "signing",
          "Con la TSL firmada y vigente, y la raíz listada, se firma",
          "With the list signed and current, and the root listed, it signs",
          "Com a TSL assinada e vigente, e a raiz listada, assina")
def _(r):
    r.sign("rsa-2048").signed()


@scenario("tsl-otro-firmante", ["F-1"], "signing",
          "TSL firmada por un certificado que no es el de la AAC: no se firma",
          "List signed by a certificate other than the AAC's: nothing is signed",
          "TSL assinada por certificado que não é o da AAC: não assina")
def _(r):
    with r.faults(trustedList="WrongSigner"):
        r.sign("rsa-2048").fails("not signed by the scheme operator")


@scenario("tsl-alterada", ["F-1"], "signing",
          "TSL alterada después de firmada: no se firma",
          "List changed after it was signed: nothing is signed",
          "TSL alterada depois de assinada: não assina")
def _(r):
    with r.faults(trustedList="Tampered"):
        r.sign("rsa-2048").fails("list was refused")


@scenario("tsl-expirada", ["F-2"], "signing",
          "TSL expirada: no se firma", "Expired list: nothing is signed", "TSL expirada: não assina")
def _(r):
    with r.faults(trustedList="Expired"):
        r.sign("rsa-2048").fails("trusted list expired")


@scenario("raiz-no-listada", ["F-3"], "signing",
          "La EC raíz del firmante no está en la lista de confianza: no se firma",
          "The signer's root CA is not among the trusted roots: nothing is signed",
          "A AC raiz do signatário não está entre as raízes de confiança: não assina")
def _(r):
    r.sign("rsa-2048", trust=["--trust-root", r.other_root()]).error("UntrustedRoot")


# -- 4.2 Signing: revocation ---------------------------------------------------------------------------------------

@scenario("crl-http", ["F-5", "F-8"], "signing",
          "Consulta de CRL por HTTP (sin OCSP disponible): se firma",
          "CRL fetched over HTTP (no OCSP available): it signs",
          "Consulta de CRL por HTTP (sem OCSP disponível): assina")
def _(r):
    with r.faults(ocsp="Down"):
        r.sign("rsa-2048").signed()
    r.sandbox_saw("crl")


@scenario("crl-https", ["F-5"], "signing",
          "Certificado cuya CRL se publica solo por HTTPS: se firma",
          "Certificate whose CRL is published over HTTPS only: it signs",
          "Certificado cuja CRL só é publicada por HTTPS: assina")
def _(r):
    r.sign("good-crl-https").signed()


@scenario("crl-ldap", ["F-5"], "signing",
          "Certificado cuya CRL se publica solo por LDAP: se firma",
          "Certificate whose CRL is published over LDAP only: it signs",
          "Certificado cuja CRL só é publicada por LDAP: assina")
def _(r):
    r.sign("good-crl-ldap").signed()


@scenario("crl-clave-ajena", ["F-6"], "signing",
          "CRL firmada con una clave que no es la de la EC: no se firma",
          "CRL signed with a key that is not the CA's: nothing is signed",
          "CRL assinada com chave que não é a da AC: não assina")
def _(r):
    with r.faults(crl="WrongKey", ocsp="Down"):
        r.sign("rsa-2048").error("RevocationStatusUnknown")


@scenario("crl-expirada", ["F-7"], "signing",
          "CRL vencida: no se firma", "Expired CRL: nothing is signed", "CRL vencida: não assina")
def _(r):
    with r.faults(crl="Expired", ocsp="Down"):
        r.sign("rsa-2048").error("RevocationStatusUnknown")


@scenario("crl-sin-proxima-actualizacion", ["F-7"], "signing",
          "CRL sin fecha de próxima actualización: no se firma",
          "CRL without a next update: nothing is signed",
          "CRL sem data de próxima atualização: não assina")
def _(r):
    with r.faults(crl="NoNextUpdate", ocsp="Down"):
        r.sign("rsa-2048").error("RevocationStatusUnknown")


@scenario("revocado", ["F-8"], "signing",
          "Certificado revocado (CRL por HTTP y OCSP): no firma",
          "Revoked certificate (CRL over HTTP and OCSP): it does not sign",
          "Certificado revogado (CRL por HTTP e OCSP): não assina")
def _(r):
    r.sign("revoked").error("CertificateRevoked")
    r.audit_has(signed=False, reason="CertificateRevoked")


@scenario("revocado-crl-https", ["F-5", "F-8"], "signing",
          "Certificado revocado, CRL solo por HTTPS: no firma",
          "Revoked certificate, CRL over HTTPS only: it does not sign",
          "Certificado revogado, CRL só por HTTPS: não assina")
def _(r):
    r.sign("revoked-crl-https").error("CertificateRevoked")


@scenario("revocado-crl-ldap", ["F-5", "F-8"], "signing",
          "Certificado revocado, CRL solo por LDAP: no firma",
          "Revoked certificate, CRL over LDAP only: it does not sign",
          "Certificado revogado, CRL só por LDAP: não assina")
def _(r):
    r.sign("revoked-crl-ldap").error("CertificateRevoked")


@scenario("revocacion-no-disponible", ["F-8", "F-14"], "signing",
          "Ni la CRL ni OCSP responden: no se firma",
          "Neither the CRL nor OCSP answers: nothing is signed",
          "Nem a CRL nem o OCSP respondem: não assina")
def _(r):
    with r.faults(crl="Down", ocsp="Down"):
        r.sign("rsa-2048").error("RevocationStatusUnknown")
    r.audit_has(signed=False, reason="RevocationStatusUnknown")


@scenario("cadena-revocada", ["F-9"], "signing",
          "La EC emisora está revocada: no se firma",
          "The issuing CA is revoked: nothing is signed",
          "A AC emissora está revogada: não assina")
def _(r):
    r.sign("under-revoked-ca").error("CertificateRevoked")


@scenario("ocsp-vigente", ["F-10"], "signing",
          "Certificado con OCSP solamente, estado bueno: se firma",
          "Certificate with OCSP only, status good: it signs",
          "Certificado só com OCSP, estado bom: assina")
def _(r):
    r.sign("good-ocsp").signed()
    r.sandbox_saw("ocsp")


@scenario("ocsp-revocado", ["F-10"], "signing",
          "Certificado con OCSP solamente, revocado: no firma",
          "Certificate with OCSP only, revoked: it does not sign",
          "Certificado só com OCSP, revogado: não assina")
def _(r):
    r.sign("revoked-ocsp").error("CertificateRevoked")


@scenario("ocsp-no-autorizado", ["F-10"], "signing",
          "Respuesta OCSP firmada por quien la EC no autorizó: no se firma",
          "OCSP response signed by a responder the CA never authorized: nothing is signed",
          "Resposta OCSP assinada por quem a AC não autorizou: não assina")
def _(r):
    with r.faults(ocsp="Unauthorized"):
        r.sign("good-ocsp").error("RevocationStatusUnknown")


# -- 4.2 Signing: validity and purpose -----------------------------------------------------------------------------

@scenario("expirado", ["F-11"], "signing",
          "Certificado expirado: no firma", "Expired certificate: it does not sign", "Certificado expirado: não assina")
def _(r):
    r.sign("expired").error("CertificateExpired")


@scenario("aun-no-valido", ["F-11"], "signing",
          "Certificado cuya vigencia aún no comienza: no firma",
          "Certificate not yet valid: it does not sign",
          "Certificado cuja vigência ainda não começou: não assina")
def _(r):
    r.sign("not-yet-valid").error("CertificateNotCurrentlyValid")


@scenario("ec-expirada", ["F-11"], "signing",
          "La EC emisora expiró: no se firma", "The issuing CA expired: nothing is signed",
          "A AC emissora expirou: não assina")
def _(r):
    r.sign("under-expired-ca").error("ChainCertificateNotValid")


@scenario("sin-no-repudio", ["F-12"], "signing",
          "Certificado sin el bit nonRepudiation: no firma",
          "Certificate without the nonRepudiation bit: it does not sign",
          "Certificado sem o bit nonRepudiation: não assina")
def _(r):
    r.sign("no-nonrepudiation").error("KeyUsageNotPermitted")


@scenario("sin-uso-de-firma", ["F-12"], "signing",
          "Certificado sin uso de clave para firmar (keyEncipherment solamente): no firma",
          "Certificate without a signing key usage (keyEncipherment only): it does not sign",
          "Certificado sem uso de chave para assinar (só keyEncipherment): não assina")
def _(r):
    r.sign("no-signing-key-usage").error("KeyUsageNotPermitted")


# -- 4.2 Signing: nothing to switch off, audit, transactions -------------------------------------------------------

@scenario("sin-opcion-de-politica", ["F-14"], "none",
          "No hay opción para cambiar la política ni saltar una verificación: una opción así es un error",
          "There is no option to change the policy or skip a check: such an option is an error",
          "Não há opção para trocar a política nem pular uma verificação: opção assim é erro")
def _(r):
    for option in (["--signing-policy", "minimal"], ["--no-revocation-check"], ["--profile", "sandbox"]):
        r.sign("rsa-2048", key="remote", extra=option).fails("Unknown option " + option[0])
    r.cli(["iofe", "sign", "--help"]).ok().lacks("--signing-policy", "--policy ", "--skip")


@scenario("contingencia", ["F-14"], "signing",
          "Sin CRL ni OCSP: solo bajo una contingencia declarada se firma, y queda en el registro",
          "No CRL nor OCSP: it signs only under a declared contingency, which goes to the record",
          "Sem CRL nem OCSP: só assina sob contingência declarada, que fica no registro")
def _(r):
    with r.faults(crl="Down", ocsp="Down"):
        r.sign("rsa-2048").error("RevocationStatusUnknown")
        r.sign("rsa-2048", contingency=("PROC-AAC-07", +2)).signed()
    r.audit_has(signed=True, policy="PROC-AAC-07")


@scenario("contingencia-revocado", ["F-14"], "signing",
          "Bajo contingencia, un certificado revocado sigue sin firmar",
          "Under a contingency a revoked certificate still does not sign",
          "Sob contingência, certificado revogado continua sem assinar")
def _(r):
    r.sign("revoked", contingency=("PROC-AAC-07", +2)).error("CertificateRevoked")


@scenario("contingencia-vencida", ["F-14"], "signing",
          "Contingencia fuera de su vigencia: se rechaza",
          "Contingency outside its validity: refused",
          "Contingência fora da vigência: recusada")
def _(r):
    r.sign("rsa-2048", contingency=("PROC-AAC-07", -2)).refused("ContingencyExpired")


@scenario("auditoria", ["F-15"], "signing",
          "Cada firma hecha o rechazada queda registrada; la cadena de registros evidencia una alteración",
          "Every signature made or refused is recorded; the chain of records shows a change",
          "Cada assinatura feita ou recusada fica registrada; a cadeia de registros evidencia alteração")
def _(r):
    r.sign("rsa-2048", transaction="factura/F001-1").signed()
    r.sign("revoked", transaction="factura/F001-2").error("CertificateRevoked")
    r.sign("rsa-2048", transaction="constancia/C-9").signed()
    r.audit_count(3)
    r.audit_has(signed=True, operation="factura/F001-1")
    r.audit_has(signed=False, operation="factura/F001-2")
    r.cli(["audit", "verify", r.audit_log]).ok().has("Intact")
    r.cli(["audit", "verify", r.tampered_copy(r.audit_log)]).fails()


@scenario("sin-registro-de-auditoria", ["F-15"], "none",
          "Sin registro de auditoría no se firma", "Without an audit log nothing is signed",
          "Sem registro de auditoria não assina")
def _(r):
    r.sign("rsa-2048", key="remote", audit=False).fails("--audit-log is required")


@scenario("transaccion-no-definida", ["F-16"], "signing",
          "Transacción de un tipo que el agente no tiene definido: se rechaza y se registra",
          "A transaction of a kind the agent was not set up for: refused and recorded",
          "Transação de tipo que o agente não tem definido: recusada e registrada")
def _(r):
    r.sign("rsa-2048", transaction="contrato/X-9").refused("TransactionNotAllowed")
    r.audit_has(signed=False, operation="contrato/X-9")


# -- 4.2 Signing: where the key is ---------------------------------------------------------------------------------

@scenario("clave-en-el-modulo", ["F-17", "F-18"], "pkcs11",
          "La clave firma dentro del módulo PKCS#11, que la declara sensible y no extraíble",
          "The key signs inside the PKCS#11 module, which reports it sensitive and not extractable",
          "A chave assina dentro do módulo PKCS#11, que a declara sensível e não extraível")
def _(r):
    r.sign("rsa-2048").signed().has("sensitive: True", "extractable: False")


@scenario("clave-extraible", ["F-18"], "pkcs11",
          "Clave que el módulo declara extraíble: se rechaza",
          "A key the module reports as extractable: refused",
          "Chave que o módulo declara extraível: recusada")
def _(r):
    r.sign("extractable").refused("KeyNotInModule")
    r.audit_has(signed=False, message="KeyNotInModule")


@scenario("modulo-no-declarado", ["F-19"], "pkcs11",
          "El token no es el módulo declarado por el operador: se rechaza",
          "The token is not the module the operator declared: refused",
          "O token não é o módulo declarado pelo operador: recusado")
def _(r):
    r.sign("rsa-2048", module={"manufacturer": "Thales", "model": "Luna K7"}).refused("ModuleMismatch")
    r.audit_has(signed=False, message="ModuleMismatch")


@scenario("clave-en-el-servicio-remoto", ["F-17", "F-18"], "remote",
          "La clave firma en el servicio de firma remota: la aplicación solo envía el resumen",
          "The key signs in the remote signing service: the application sends the hash only",
          "A chave assina no serviço de assinatura remota: a aplicação só envia o resumo")
def _(r):
    r.sign("rsa-2048").signed().has("in the remote service")
    r.sandbox_saw("csc")
    r.audit_has(signed=True, policy="firma remota")


@scenario("servicio-no-declarado", ["F-19"], "remote",
          "El servicio de firma remota no es el declarado: se rechaza antes de enviarle secreto alguno",
          "The remote signing service is not the declared one: refused before any secret is sent to it",
          "O serviço de assinatura remota não é o declarado: recusado antes de lhe enviar qualquer segredo")
def _(r):
    r.sign("rsa-2048", service_name="Otro Servicio").refused("RemoteServiceMismatch")
    r.audit_has(signed=False, message="RemoteServiceMismatch")


@scenario("credencial-con-persona", ["F-16"], "remote",
          "Credencial remota que debe autorizar una persona: un agente desatendido la rechaza",
          "A remote credential a person has to authorize: an unattended agent refuses it",
          "Credencial remota que uma pessoa precisa autorizar: o agente desatendido recusa")
def _(r):
    r.sign("rsa-2048", credential="rsa-oauth").refused("RemoteAuthorizationNotUnattended")


@scenario("pin-incorrecto", ["F-17"], "signing",
          "PIN incorrecto: no se firma", "Wrong PIN: nothing is signed", "PIN incorreto: não assina")
def _(r):
    r.sign("rsa-2048", pin="9999").fails()
    r.audit_lacks_signed()


@scenario("pfx-no-aceptado", ["F-17", "F-18"], "none",
          "Un archivo PKCS#12 (PFX) no es una fuente de clave: no hay opción para usarlo",
          "A PKCS#12 (PFX) file is not a key source: there is no option to use one",
          "Um arquivo PKCS#12 (PFX) não é fonte de chave: não há opção para usá-lo")
def _(r):
    pfx = r.pfx("rsa-2048")
    r.sign("rsa-2048", key=None, extra=["--cert", pfx, "--password", r.audit_env.info["pfxPassword"]]).fails(
        "--pkcs11-lib (a cryptographic module) or --csc-url (a remote signing service)")
    r.sign("rsa-2048", key="remote", extra=["--cert", pfx]).fails("Unknown option --cert")
    r.cli(["iofe", "sign", "--help"]).ok().lacks("--cert ", "--password")


# -- 4.2 Signing: algorithms, viewer, validation data --------------------------------------------------------------

@scenario("clave-debil", ["F-28"], "signing",
          "Clave RSA de 1024 bits: no firma", "RSA 1024-bit key: it does not sign", "Chave RSA de 1024 bits: não assina")
def _(r):
    r.sign("rsa-1024").error("KeyTooWeak")


@scenario("sha1-en-la-cadena", ["F-28"], "signing",
          "Cadena con un certificado firmado con SHA-1: no se firma",
          "A chain with a certificate signed with SHA-1: nothing is signed",
          "Cadeia com certificado assinado com SHA-1: não assina")
def _(r):
    r.sign("under-sha1-ca").error("AlgorithmNotPermitted").has("SHA1")


@scenario("algoritmos-vigentes", ["F-28"], "signing",
          "RSA 3072 y 4096, ECDSA P-256 y P-384: se firma",
          "RSA 3072 and 4096, ECDSA P-256 and P-384: it signs",
          "RSA 3072 e 4096, ECDSA P-256 e P-384: assina")
def _(r):
    for signer in ("rsa-3072", "rsa-4096", "ecdsa-p256", "ecdsa-p384"):
        r.sign(signer).signed()


@scenario("visor", ["F-30"], "signing",
          "El visor muestra integridad, fecha y hora, clave pública y datos del certificado",
          "The viewer shows integrity, signing time, public key and certificate data",
          "O visor mostra integridade, data e hora, chave pública e dados do certificado")
def _(r):
    signed = r.sign("rsa-2048").signed().output
    page = r.path("visor.html")
    r.cli(["iofe", "view", signed, "--output", page] + r.trust()).ok()
    r.file_has(page, "Maria da Silva", "BEGIN PUBLIC KEY")


@scenario("datos-de-validacion", ["F-31", "S-1", "S-2", "S-3", "S-4"], "signing",
          "Con la autoridad de sellado de tiempo: sello verificado, cadena y datos de revocación incluidos (B-LT)",
          "With the time-stamp authority: token checked, chain and revocation data embedded (B-LT)",
          "Com a autoridade de carimbo de tempo: carimbo verificado, cadeia e dados de revogação incluídos (B-LT)")
def _(r):
    signed = r.sign("rsa-2048", tsa="tsa").signed().has("LongTerm").output
    r.cli(["inspect", signed]).ok().has("Timestamp")
    r.verify(signed).accepted()


@scenario("formatos", ["F-31"], "signing",
          "Firma de XML (XAdES) y de cualquier archivo (CMS, CAdES), que el agente de verificación acepta",
          "Signature of XML (XAdES) and of any file (CMS, CAdES), which the verification agent accepts",
          "Assinatura de XML (XAdES) e de qualquer arquivo (CMS, CAdES), que o agente de verificação aceita")
def _(r):
    xml = r.sign("rsa-2048", document="xml").signed().output
    cms = r.sign("rsa-2048", document="bin").signed().output
    r.verify(xml).accepted()
    r.verify(cms).accepted()


# -- 4.4 Time-stamps -----------------------------------------------------------------------------------------------

@scenario("tsa-otra-autoridad", ["S-1"], "signing",
          "El sello proviene de otra autoridad que la configurada: se rechaza",
          "The token comes from another authority than the one configured: refused",
          "O carimbo vem de outra autoridade que a configurada: recusado")
def _(r):
    r.sign("rsa-2048", tsa="tsa", tsa_url="revokedUrl").error("TimestampUntrusted").has("not by the expected TSA")


@scenario("tsa-sello-alterado", ["S-2"], "signing",
          "Sello de tiempo con la firma alterada: se rechaza",
          "A time-stamp whose signature was changed: refused",
          "Carimbo de tempo com a assinatura alterada: recusado")
def _(r):
    with r.faults(tsa="InvalidToken"):
        r.sign("rsa-2048", tsa="tsa").fails("token signature", "invalid")


@scenario("tsa-revocada", ["S-3"], "signing",
          "Certificado de la autoridad de sellado de tiempo revocado: se rechaza",
          "The time-stamp authority's certificate is revoked: refused",
          "Certificado da autoridade de carimbo de tempo revogado: recusado")
def _(r):
    r.sign("rsa-2048", tsa="tsa-revoked", tsa_url="revokedUrl").error("TimestampCertificateRevoked")


@scenario("tsa-expirada", ["S-4"], "signing",
          "Certificado de la autoridad de sellado de tiempo expirado: se rechaza",
          "The time-stamp authority's certificate expired: refused",
          "Certificado da autoridade de carimbo de tempo expirado: recusado")
def _(r):
    r.sign("rsa-2048", tsa="tsa-expired", tsa_url="expiredUrl").error("TimestampCertificateNotValid")


# -- 4.3 Verification ----------------------------------------------------------------------------------------------

@scenario("v-valido", ["V-1", "V-3", "V-5", "V-10", "V-11", "V-12", "V-15"], "none",
          "Documento con firma válida de un certificado de la lista: se acepta y se registra",
          "A document validly signed with a certificate of the list: accepted and recorded",
          "Documento com assinatura válida de certificado da lista: aceito e registrado")
def _(r):
    r.verify(r.sample("rsa-2048")).accepted()
    r.verification_has(accepted=True)


@scenario("v-tsl-otro-firmante", ["V-1"], "none",
          "TSL firmada por otro certificado: la verificación no se realiza",
          "List signed by another certificate: the verification does not go on",
          "TSL assinada por outro certificado: a verificação não se realiza")
def _(r):
    sample = r.sample("rsa-2048")
    with r.faults(trustedList="WrongSigner"):
        r.verify(sample).fails("not signed by the scheme operator")


@scenario("v-tsl-expirada", ["V-2"], "none",
          "TSL expirada: el documento no se acepta", "Expired list: the document is not accepted",
          "TSL expirada: o documento não é aceito")
def _(r):
    sample = r.sample("rsa-2048")
    with r.faults(trustedList="Expired"):
        r.verify(sample).fails("trusted list expired")


@scenario("v-raiz-no-listada", ["V-3"], "none",
          "Firmante cuya EC raíz no está entre las de confianza: se rechaza",
          "A signer whose root CA is not trusted: rejected",
          "Signatário cuja AC raiz não está entre as de confiança: rejeitado")
def _(r):
    r.verify(r.sample("rsa-2048"), trust=["--trust-root", r.other_root()]).rejected("NoCertificateChainFound")


@scenario("v-revocado", ["V-5", "V-8", "V-9", "V-10"], "none",
          "Documento firmado con un certificado que luego fue revocado: se rechaza, con comunicado al emisor",
          "A document signed with a certificate revoked afterwards: rejected, with a notice to its sender",
          "Documento assinado com certificado depois revogado: rejeitado, com comunicado ao remetente")
def _(r):
    r.verify(r.sample("revoked")).rejected("RevokedNoPoe")
    r.notice_has(SENDER)
    r.verification_has(accepted=False)


@scenario("v-revocado-crl-https", ["V-5"], "none",
          "Firmante revocado cuya CRL se publica solo por HTTPS: se rechaza",
          "A revoked signer whose CRL is published over HTTPS only: rejected",
          "Signatário revogado cuja CRL só é publicada por HTTPS: rejeitado")
def _(r):
    r.verify(r.sample("revoked-crl-https")).rejected("RevokedNoPoe")


@scenario("v-revocado-crl-ldap", ["V-5"], "none",
          "Firmante revocado cuya CRL se publica solo por LDAP: se rechaza",
          "A revoked signer whose CRL is published over LDAP only: rejected",
          "Signatário revogado cuja CRL só é publicada por LDAP: rejeitado")
def _(r):
    r.verify(r.sample("revoked-crl-ldap")).rejected("RevokedNoPoe")


@scenario("v-crl-clave-ajena", ["V-6"], "none",
          "CRL firmada con una clave que no es la de la EC: el documento no se acepta",
          "CRL signed with a key that is not the CA's: the document is not accepted",
          "CRL assinada com chave que não é a da AC: o documento não é aceito")
def _(r):
    sample = r.sample("rsa-2048")
    with r.faults(crl="WrongKey", ocsp="Down"):
        r.verify(sample).rejected("CertificateChainGeneralFailure")


@scenario("v-crl-expirada", ["V-7"], "none",
          "CRL vencida: el documento no se acepta", "Expired CRL: the document is not accepted",
          "CRL vencida: o documento não é aceito")
def _(r):
    sample = r.sample("rsa-2048")
    with r.faults(crl="Expired", ocsp="Down"):
        r.verify(sample).rejected("CertificateChainGeneralFailure")


@scenario("v-cadena-revocada", ["V-9"], "none",
          "La EC emisora del firmante está revocada: se rechaza",
          "The signer's issuing CA is revoked: rejected",
          "A AC emissora do signatário está revogada: rejeitado")
def _(r):
    r.verify(r.sample("under-revoked-ca")).rejected("RevokedCaNoPoe")


@scenario("v-ocsp-revocado", ["V-10"], "none",
          "Firmante con OCSP solamente, revocado: se rechaza",
          "A signer with OCSP only, revoked: rejected",
          "Signatário só com OCSP, revogado: rejeitado")
def _(r):
    r.verify(r.sample("revoked-ocsp")).rejected("RevokedNoPoe")


@scenario("v-expirado", ["V-11"], "none",
          "Documento firmado con un certificado que ya expiró: se rechaza",
          "A document signed with a certificate that has expired: rejected",
          "Documento assinado com certificado que já expirou: rejeitado")
def _(r):
    r.verify(r.expired_sample()).rejected("OutOfBoundsNoPoe")


@scenario("v-sin-no-repudio", ["V-12"], "none",
          "Firmante sin el bit nonRepudiation: se rechaza",
          "A signer without the nonRepudiation bit: rejected",
          "Signatário sem o bit nonRepudiation: rejeitado")
def _(r):
    r.verify(r.sample("no-nonrepudiation")).rejected("ChainConstraintsFailure")


@scenario("v-sin-opcion-de-politica", ["V-14"], "none",
          "No hay opción para cambiar la política de verificación: una opción así es un error",
          "There is no option to change the verification policy: such an option is an error",
          "Não há opção para trocar a política de verificação: opção assim é erro")
def _(r):
    r.verify(r.sample("rsa-2048"), extra=["--policy", "default"]).fails("Unknown option --policy")
    r.cli(["iofe", "verify", "--help"]).ok().lacks("--policy ", "--skip")


@scenario("v-contingencia", ["V-14"], "none",
          "Sin CRL ni OCSP: se rechaza; bajo una contingencia declarada se acepta y queda en el registro",
          "No CRL nor OCSP: rejected; under a declared contingency it is accepted and recorded",
          "Sem CRL nem OCSP: rejeitado; sob contingência declarada é aceito e fica no registro")
def _(r):
    sample = r.sample("rsa-2048")
    with r.faults(crl="Down", ocsp="Down"):
        r.verify(sample).rejected("CertificateChainGeneralFailure")
        r.verify(sample, contingency=("PROC-AAC-07", +2)).accepted()


@scenario("v-contingencia-revocado", ["V-14"], "none",
          "Bajo contingencia, un firmante revocado sigue rechazado",
          "Under a contingency a revoked signer is still rejected",
          "Sob contingência, signatário revogado continua rejeitado")
def _(r):
    r.verify(r.sample("revoked"), contingency=("PROC-AAC-07", +2)).rejected("RevokedNoPoe")


@scenario("v-auditoria", ["V-15"], "none",
          "Cada verificación, aceptada o rechazada, queda registrada; la cadena evidencia una alteración",
          "Every verification, accepted or rejected, is recorded; the chain shows a change",
          "Cada verificação, aceita ou rejeitada, fica registrada; a cadeia evidencia alteração")
def _(r):
    r.verify(r.sample("rsa-2048")).accepted()
    r.verify(r.sample("revoked")).rejected("RevokedNoPoe")
    r.verification_count(2)
    r.cli(["audit", "verify", r.verification_log]).ok().has("Intact")
    r.cli(["audit", "verify", r.tampered_copy(r.verification_log)]).fails()


@scenario("v-clave-debil", ["V-28"], "none",
          "Firmante con clave RSA de 1024 bits: se rechaza",
          "A signer with an RSA 1024-bit key: rejected",
          "Signatário com chave RSA de 1024 bits: rejeitado")
def _(r):
    r.verify(r.sample("rsa-1024")).rejected("CryptoConstraintsFailureNoPoe")


@scenario("v-documento-alterado", ["V-30"], "none",
          "Documento alterado después de la firma: se rechaza, con comunicado al emisor",
          "A document changed after it was signed: rejected, with a notice to its sender",
          "Documento alterado depois da assinatura: rejeitado, com comunicado ao remetente")
def _(r):
    r.verify(r.changed_copy(r.sample("rsa-2048"))).rejected("HashFailure")
    r.notice_has(SENDER)


@scenario("v-sin-firmas", ["V-30"], "none",
          "Documento sin firmas: se rechaza, con comunicado al emisor",
          "A document without signatures: rejected, with a notice to its sender",
          "Documento sem assinaturas: rejeitado, com comunicado ao remetente")
def _(r):
    r.verify(r.document("pdf")).rejected().has("no contiene firmas")
    r.notice_has(SENDER)


@scenario("v-visor", ["V-30"], "none",
          "El visor muestra los datos de la firma de un documento recibido",
          "The viewer shows the data of the signature of a received document",
          "O visor mostra os dados da assinatura de um documento recebido")
def _(r):
    page = r.path("visor.html")
    r.cli(["iofe", "view", r.sample("rsa-2048"), "--output", page] + r.trust()).ok()
    r.file_has(page, "Maria da Silva")


# ── The run ──────────────────────────────────────────────────────────────────────────────────────────────────────

class Problem(Exception):
    """The environment is not what the script needs."""


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

    def has(self, *texts):
        for text in texts:
            self._check({"key": "exp_text", "detail": text}, text.lower() in self.flat.lower())
        return self

    def lacks(self, *texts):
        for text in texts:
            self._check({"key": "exp_text", "detail": f"≠ {text.strip()}"}, text.lower() not in self.text.lower(),
                        {"key": "no" if text.lower() not in self.text.lower() else "yes"})
        return self


class Run:
    """One scenario, with one key source: its folder, its commands and what they showed."""

    def __init__(self, audit, scn, key, number):
        self.audit_env, self.scenario, self.key = audit, scn, key
        suffix = "" if key in (None, "none") else f"-{key}"
        self.folder = audit.out / f"{number:02d}-{scn.id}{suffix}"
        self.folder.mkdir(parents=True, exist_ok=True)
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
        return list(self.audit_env.trust)

    def other_root(self):
        return self.audit_env.other_root()

    def pfx(self, signer):
        return self.audit_env.pfx(signer)

    def sample(self, signer):
        return self.audit_env.sample(signer)

    def expired_sample(self):
        return self.audit_env.expired_sample()

    @contextlib.contextmanager
    def faults(self, **faults):
        self.sandbox_changes.append("faults: " + ", ".join(f"{k}={v}" for k, v in faults.items()))
        self.say("Sandbox  PUT /api/faults  " + json.dumps(faults))
        self.audit_env.api("PUT", "/api/faults", faults)
        try:
            yield
        finally:
            self.audit_env.api("DELETE", "/api/faults")
            self.say("Sandbox  DELETE /api/faults")

    def cli(self, arguments, output=None):
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
             trust=None, tsa=None, tsa_url=None, contingency=None, extra=(), audit=True, module=None,
             service_name=None, credential=None, pin=None):
        env = self.audit_env
        key = self.key if key == "default" else key
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
            arguments += ["--tsa", env.info["tsa"][tsa_url or "url"], "--tsa-cert", env.certificate_pem(tsa)]
        if contingency:
            arguments += env.contingency_arguments(*contingency)
        return self.cli(arguments + list(extra), output)

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
        content = pathlib.Path(path).read_text(encoding="utf-8-sig", errors="replace") if os.path.exists(path) else ""
        for text in texts:
            self._extra({"key": "exp_text", "detail": f"{os.path.basename(path)}: {text}"}, text in content,
                        {"key": "yes" if text in content else "no"})

    def sandbox_saw(self, service):
        """The Sandbox's own log shows the agent asked that service during the last command."""
        requests = getattr(self.steps[-1], "sandbox_requests", []) if self.steps else []
        hits = [request for request in requests if service in str(request.get("service", "")).lower()
                or f"/{service}" in str(request.get("path", "")).lower()]
        self._extra({"key": "exp_text", "detail": f"Sandbox log: {service}"}, bool(hits),
                    f"{len(hits)} request(s)" if hits else "—")

    def tampered_copy(self, path):
        """A copy of an audit trail with one record changed."""
        copy = self.path("alterado-" + os.path.basename(path))
        text = pathlib.Path(path).read_text(encoding="utf-8-sig")
        changed = text.replace('"signed":true', '"signed":false', 1) if '"signed":true' in text \
            else text.replace('"accepted":false', '"accepted":true', 1) if '"accepted":false' in text \
            else text.replace("factura", "FACTURA", 1)
        pathlib.Path(copy).write_text(changed, encoding="utf-8")
        return copy

    def changed_copy(self, path):
        """A copy of a signed document with one byte of what is signed changed."""
        copy = self.path("alterado-" + os.path.basename(path))
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
        if self.audit_env.live or self.audit_env.verbose:
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
                out.write(f"# Sandbox: {change}\n")
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

    def __init__(self, options):
        self.sandbox = options.sandbox.rstrip("/")
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
        return str(path)

    def other_root(self):
        """A root that issued none of the Sandbox's certificates: the TSA's own self-signed CA."""
        path = self.work / "otra-raiz.pem"
        if not path.exists():
            content = self.api("GET", "/aia/tsa-ca.cer", raw=True)
            body = base64.encodebytes(content).decode().strip()
            path.write_text(f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n", encoding="utf-8")
        return str(path)

    def sample(self, signer):
        """
        A document as a third party would send it, signed with a Sandbox certificate. It is made with the general
        signer under its most permissive policy, so a revoked or weak certificate signs: the verification agent,
        not the signer, is what a verification scenario tests.
        """
        if signer not in self._samples:
            path = self.work / f"recibido-{signer}.pdf"
            command, code, text = self.run_cli(["sign", self.document("pdf"), "--output", str(path), "--cert", self.pfx(signer),
                                                "--password", self.info["pfxPassword"], "--signing-policy", "minimal"])
            if code != 0 or not path.exists():
                raise Problem(f"The test document of '{signer}' could not be prepared:\n$ {command}\n{text}")
            self._samples[signer] = str(path)
        return self._samples[signer]

    def expired_sample(self):
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
    return tr("skipped", lang) if run.get("skipped") else tr("passed" if run["passed"] else "failed", lang)


def report_markdown(results, env, lang):
    lines = [f"# {tr('title', lang)}", "", tr("intro", lang), "",
             f"- {tr('generated', lang)}: {env['time']}",
             f"- {tr('environment', lang)}: {env['cli']} · Sandbox {env['sandbox']} · {env['platform']}", ""]
    done = [r for r in results if not r.get("skipped")]
    lines += [f"## {tr('summary', lang)}", "",
              f"{tr('passed', lang)}: {sum(1 for r in done if r['passed'])} · "
              f"{tr('failed', lang)}: {sum(1 for r in done if not r['passed'])} · "
              f"{tr('skipped', lang)}: {sum(1 for r in results if r.get('skipped'))}", "",
              f"## {tr('by_item', lang)}", "",
              f"| {tr('item', lang)} | {tr('asks', lang)} | {tr('scenarios', lang)} | {tr('result', lang)} |",
              "|---|---|---|---|"]
    for item in all_items():
        of_item = [r for r in results if item in r["items"]]
        if not of_item and not item_text(item, lang):
            continue
        names = ", ".join(sorted({r["id"] for r in of_item})) or f"_{tr('no_scenario', lang)}_"
        ran = [r for r in of_item if not r.get("skipped")]
        outcome = "—" if not ran else tr("passed" if all(r["passed"] for r in ran) else "failed", lang)
        lines.append(f"| {item} | {item_text(item, lang)} | {names} | {outcome} |")
    lines += ["", f"## {tr('scenarios', lang)}", ""]
    for r in results:
        key = tr("key_" + (r["key"] or "none"), lang)
        lines += [f"### {r['folder']} — {r['title'][lang]}", "",
                  f"{tr('item', lang)}: {', '.join(r['items'])} · {tr('key', lang)}: {key} · "
                  f"**{status(r, lang)}**" + (f" ({r['skipped']})" if r.get("skipped") else ""), ""]
        if r.get("skipped"):
            continue
        for change in r["sandbox"]:
            lines.append(f"- {tr('sandbox', lang)}: `{change}`")
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
    done = [r for r in results if not r.get("skipped")]
    rows = []
    for item in all_items():
        of_item = [r for r in results if item in r["items"]]
        if not of_item and not item_text(item, lang):
            continue
        ran = [r for r in of_item if not r.get("skipped")]
        css = "none" if not ran else ("ok" if all(r["passed"] for r in ran) else "bad")
        outcome = "—" if not ran else tr("passed" if css == "ok" else "failed", lang)
        names = ", ".join(f'<a href="#{e(r["folder"])}">{e(r["id"])}</a>' for r in of_item) \
            or f"<em>{e(tr('no_scenario', lang))}</em>"
        rows.append(f'<tr><td>{item}</td><td>{e(item_text(item, lang))}</td><td>{names}</td>'
                    f'<td class="{css}">{e(outcome)}</td></tr>')
    sections = []
    for r in results:
        css = "none" if r.get("skipped") else ("ok" if r["passed"] else "bad")
        body = [f'<section id="{e(r["folder"])}"><h3>{e(r["folder"])} — {e(r["title"][lang])} '
                f'<span class="{css}">{e(status(r, lang))}</span></h3>',
                f'<p>{e(tr("item", lang))}: {e(", ".join(r["items"]))} · {e(tr("key", lang))}: '
                f'{e(tr("key_" + (r["key"] or "none"), lang))}'
                + (f' · {e(r["skipped"])}' if r.get("skipped") else "") + "</p>"]
        if not r.get("skipped"):
            for change in r["sandbox"]:
                body.append(f'<p>{e(tr("sandbox", lang))}: <code>{e(change)}</code></p>')
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
<p>{e(tr('intro', lang)).replace('`', '')}</p>
<p>{e(tr('generated', lang))}: {e(env['time'])} · {e(tr('environment', lang))}: {e(env['cli'])} · Sandbox {e(env['sandbox'])} · {e(env['platform'])}</p>
<h2>{e(tr('summary', lang))}</h2>
<p><span class="ok">{e(tr('passed', lang))}: {sum(1 for r in done if r['passed'])}</span> ·
<span class="bad">{e(tr('failed', lang))}: {sum(1 for r in done if not r['passed'])}</span> ·
<span class="none">{e(tr('skipped', lang))}: {sum(1 for r in results if r.get('skipped'))}</span></p>
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

def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sandbox", default=os.environ.get("SANDBOX_URL", "http://localhost:5300"), help="the running Sandbox")
    parser.add_argument("--cli", default="simplesign", help='the command line with the IOFE extension (default: "simplesign")')
    parser.add_argument("--key", choices=("remote", "pkcs11", "both"), default="remote", help="where the signing key is")
    parser.add_argument("--pkcs11-lib", help="the PKCS#11 library of the token (default: SoftHSM2, where it is found)")
    parser.add_argument("--out", default="evidencias", help="the folder of the evidence (default: ./evidencias)")
    parser.add_argument("--lang", choices=LANGS, default="es", help="the language of what is printed (the report comes in the three)")
    parser.add_argument("--item", action="append", default=[], help="only the scenarios of this item of annex B (F-8); repeatable")
    parser.add_argument("--scenario", action="append", default=[], help="only this scenario; repeatable")
    parser.add_argument("--list", action="store_true", help="list the scenarios and stop")
    parser.add_argument("--write-catalog", action="store_true", help="write escenarios.json and stop")
    parser.add_argument("-v", "--verbose", action="store_true", help="print every command and its output")
    options = parser.parse_args()
    options.live = bool(options.item or options.scenario)

    if options.write_catalog:
        write_catalog()
        return 0
    chosen = [s for s in SCENARIOS
              if (not options.item or set(i.upper() for i in options.item) & set(s.items))
              and (not options.scenario or s.id in options.scenario)]
    if options.list:
        for s in chosen:
            print(f"{s.id:32} {','.join(s.items):24} {s.keys:8} {s.titles[options.lang]}")
        return 0
    if not chosen:
        print("No scenario matches.", file=sys.stderr)
        return 2

    env = Audit(options)
    try:
        env.prepare()
    except Problem as problem:
        print(f"✗ {problem}", file=sys.stderr)
        return 2
    sources = ["remote", "pkcs11"] if options.key == "both" else [options.key]

    results, number = [], 0
    for scn in chosen:
        keys = sources if scn.keys == "signing" else [scn.keys] if scn.keys in ("pkcs11", "remote") else [None]
        for key in keys:
            number += 1
            run = Run(env, scn, key, number)
            record = {"id": scn.id, "items": scn.items, "title": scn.titles, "key": key, "folder": run.folder.name}
            skipped = None
            if key == "pkcs11" and (scn.keys == "pkcs11" or "pkcs11" in sources) and not env.has_token():
                skipped = tr("no_token", options.lang)
            elif key in ("pkcs11", "remote") and key not in sources:
                skipped = f"--key {key}"
            label = f"[{number:02d}] {scn.id}" + (f" ({key})" if key else "")
            if skipped:
                print(f"– {label}: {tr('skipped', options.lang)} ({skipped})")
                shutil.rmtree(run.folder, ignore_errors=True)
                results.append({**record, "skipped": skipped, "passed": False})
                continue
            if options.live or options.verbose:
                print(f"\n▶ {label} — {scn.titles[options.lang]}  [{', '.join(scn.items)}]")
            try:
                scn.run(run)
            except Problem as problem:
                run.error = str(problem)
            except Exception as error:  # a scenario that breaks is a failed scenario, not a failed run
                run.error = f"{type(error).__name__}: {error}"
            finally:
                with contextlib.suppress(Exception):
                    env.api("DELETE", "/api/faults")
            run.save()
            mark = "✓" if run.passed else "✗"
            print(f"{mark} {label}: {tr('passed' if run.passed else 'failed', options.lang)}"
                  + (f" — {run.error}" if run.error else ""))
            if not run.passed and not (options.live or options.verbose):
                for check in run.checks:
                    if not check.ok:
                        print(f"     {tr('expected', options.lang)}: {phrase(check.expected, options.lang)} · "
                              f"{tr('found', options.lang)}: {phrase(check.found, options.lang)}")
            results.append({**record, "passed": run.passed, "error": run.error, "sandbox": run.sandbox_changes,
                            "steps": [{"command": s.command, "exit": s.exit, "text": s.text,
                                       "checks": [vars(c) for c in s.checks]} for s in run.steps],
                            "checks": [vars(c) for c in run.extra_checks]})

    command, _, version = env.run_cli(["version"])
    meta = {"time": datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z"),
            "cli": " ".join(version.split()) or command, "sandbox": f"{env.sandbox} ({env.info.get('version', '')})",
            "platform": f"{sys.platform}, Python {sys.version.split()[0]}"}
    (env.out / "resultados.json").write_text(json.dumps({"environment": meta, "results": results}, indent=1,
                                                         ensure_ascii=False), encoding="utf-8")
    for lang in LANGS:
        (env.out / f"informe.{lang}.md").write_text(report_markdown(results, meta, lang), encoding="utf-8")
        (env.out / f"informe.{lang}.html").write_text(report_html(results, meta, lang), encoding="utf-8")

    done = [r for r in results if not r.get("skipped")]
    failed = [r for r in done if not r["passed"]]
    print(f"\n{tr('passed', options.lang)}: {len(done) - len(failed)} · {tr('failed', options.lang)}: {len(failed)} · "
          f"{tr('skipped', options.lang)}: {len(results) - len(done)}")
    print(f"{tr('evidence', options.lang)}: {env.out}{os.sep}informe.{options.lang}.html")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
