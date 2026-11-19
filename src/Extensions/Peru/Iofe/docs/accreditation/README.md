# Accreditation by INDECOPI — SimpleSign.Peru.Iofe.Accredited

Documentation of SimpleSign's accreditable configuration for Peru's Infraestructura Oficial de Firma Electrónica
(IOFE), under the *Guía de Acreditación de Aplicaciones de Software*, version 4.0 (INDECOPI, 2016), for these types
of application. These manuals are also in Spanish, the version handed to INDECOPI:
[`es/acreditacion/`](../es/acreditacion/README.md). The English text is the main one; the Spanish is its translation.

| Section of the guide | Type | Component |
|---|---|---|
| 4.2 (Req. 11–20) | Signing software for automated agents, with the key in a cryptographic module (PKCS#11) or in a remote signing service | `IofeSigningAgent` · `simplesign iofe sign` |
| 4.3 (Req. 21–30) | Verification software for automated agents | `IofeVerificationAgent` · `simplesign iofe verify` |
| 4.4 | Time-stamp requests | `IofeTimestampAuthority` |

End-user signing software (section 4.1) is not part of this package, nor is signing with PKCS#12 (PFX) files, which
contradicts Req. 15.

| Document | For whom | Requirement |
|---|---|---|
| [Scope](scope.md) | The auditor: the scope data annex B asks for | Annex B |
| [Administration manual](administration-manual.md) | Whoever installs, configures and operates the solution | Req. 20, 30 |
| [User manual](user-manual.md) | Whoever runs the commands and reads the results | Req. 20, 30 |
| [Programmer's manual](programmer-manual.md) | Whoever integrates the library | Req. 20 ("manual de programador") |
| [Security configuration](security-configuration.md) | The users of the accredited application | Section 5 |

What shows each item of annex B is in
[`src/Extensions/Peru/Iofe/playbooks/indecopi-checklist.md`](../../playbooks/indecopi-checklist.md). The
[audit walk-through](../audit-walkthrough.md) ([español](../es/guion-de-auditoria.md)) says how to produce and
present that evidence with the accredited configuration.

INDECOPI grants the accreditation to a product and its operation. This package is the software part; the manuals say
what stays with the operator (the certification of the cryptographic module or the accreditation of the remote
signing service, key custody, access control of the system).
