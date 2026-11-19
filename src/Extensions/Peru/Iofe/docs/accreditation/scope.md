# Scope of the accreditation

The data annex B of the guide asks to be recorded in the audit report. (In Spanish, the version handed to INDECOPI:
[`alcance.md`](../es/acreditacion/alcance.md).)

| | Data | Value |
|---|---|---|
| a | Name of the application | SimpleSign.Peru.Iofe.Accredited (NuGet package) and `simplesign iofe` (command line: the SimpleSign.Cli tool with the SimpleSign.Peru.Iofe.Cli extension). The version is the package's: `dotnet list package` or `simplesign version` |
| b | PKI functions | Digital signature and verification of digital signatures. No authentication, no encryption |
| c | Revocation status query | CRL (HTTP, HTTPS and LDAP; RFC 5280) and OCSP (RFC 2560). OCSP is asked first, the CRL after |
| d | Type of operation | A library for servers and unattended processes; a command line |
| e | Operating systems | Windows, Linux and macOS with .NET 8 or .NET 10 |
| f | Format of the signed document | PDF (PAdES, ETSI EN 319 142), CMS (CAdES, ETSI EN 319 122) and XML (XAdES, ETSI EN 319 132) |
| g | Does it perform cryptographic-module functions? | No. The private-key operation is done in the operator's cryptographic module, through PKCS#11, or in that of a declared remote signing service (Cloud Signature Consortium API v2). The library computes the hash (SHA-256 or stronger) with `System.Security.Cryptography`, and the hash is all it sends |
| h | Does it make copies of the private key? | No. The library does not read, export or store the key, refuses a key the module reports as extractable and does not accept PKCS#12 (PFX) files |
| i | Format of the document to sign | PDF; XML; any file, for a CMS signature |
| j | Tools of the test environment | SimpleSign Sandbox (a test PKI with CRL, OCSP, TSA, a trusted list and a remote signing service); the script `tools/auditoria/auditoria.py`, which runs `simplesign iofe` for each item of annex B and keeps the evidence ([audit walk-through](../audit-walkthrough.md)), against the Sandbox or, with `--entorno`, in the real environment: the operator's HSM, INDECOPI's list and the real CA; SoftHSM2 as the test PKCS#11 module. The SimpleSign TestBench (playbook `indecopi-guia-v4`) uses the general signers and is complementary material |
| k | Does it request time-stamps? | Yes, optionally (RFC 3161), with the checks of section 4.4 |

## Types of application

- **Signing by an automated agent (4.2).** A legal person signs unattended with one key, kept in its cryptographic
  module. The module is part of the scope: the operator declares its manufacturer, model and FIPS 140-2 or Common
  Criteria EAL 4+ certificate.
  Alternatively the key may be kept by a **remote signing service**: the operator declares the provider and its
  accreditation, and the cryptographic module — the provider's — is not part of the solution.
- **Verification by an automated agent (4.3).** The system receives signed documents and checks, without operators,
  the certificate of each signature. The verification agent of this package **does not sign** the documents it
  receives; requirements 25, 28 and 29, which apply when the system signs, therefore do not apply to it. A product
  that needs to sign them does so with an `IofeSigningAgent`, which does meet them.
- **Time-stamps (4.4).** Optional, within the signing agent.

## Optional requirement: the trusted list (TSL)

Its evaluation is requested. By default the application trusts INDECOPI's list
(<https://iofe.indecopi.gob.pe/TSL/tsl-pe.xml>): it checks its signature against the certificate INDECOPI signs it
with, refuses an expired list, checks that the certificate's root CA is in it and downloads it again every 6 hours
and when its next update comes. The alternative the guide allows — root certificates installed by the operator — is
available with `IofeTrust.InstalledRoots`.

## Declaration of non-applicability

| Item | Reason |
|---|---|
| Req. 25, 28, 29 and their items of annex B (V-17 to V-27, V-30, V-31) | The verification agent does not sign the documents it receives |
| Items "when the private key is part of the solution" (F-20 to F-27) | They concern the operation of the cryptographic module: see the administration manual. With the key in a remote signing service they do not apply: the key and its module are the provider's |
| Signing with PKCS#12 (PFX) files | Outside the scope: it contradicts Req. 15. The signing agent does not accept them (administration manual, section 3.3) |
