# User manual

For whoever runs the `simplesign iofe` command line and reads its results. The `iofe` commands come with the
extension `SimpleSign.Peru.Iofe.Cli` (`simplesign extension install SimpleSign.Peru.Iofe.Cli`; see the administration
manual). (In Spanish, the version handed to INDECOPI: [`manual-de-usuario.md`](../es/acreditacion/manual-de-usuario.md).)

## Signing as an automated agent

```bash
simplesign iofe sign factura.pdf --output factura-firmada.pdf \
  --pkcs11-lib /usr/lib/libCryptoki2_64.so --pkcs11-token firma --pkcs11-key sello-2026 --pin env:HSM_PIN \
  --module-manufacturer "Thales" --module-model "Luna K7" \
  --module-certification "FIPS 140-2 Level 3" --module-certificate 4090 \
  --transaction factura/F001-123 --allow factura --allow constancia \
  --audit-log /var/log/firma/auditoria.jsonl \
  --tsa https://tsa.example.pe/tsa --tsa-cert tsa.pem
```

With the key in a remote signing service, instead of the `--pkcs11-…` and `--module-…` options:

```bash
simplesign iofe sign factura.pdf --output factura-firmada.pdf \
  --csc-url https://provider.example.pe/csc/v2/ --csc-credential sello-2026 --pin env:CSC_PIN \
  --csc-client-id agente-de-firma --csc-client-secret env:CSC_SECRET \
  --service-provider "Proveedor S.A." --service-name "Firma Remota" \
  --service-accreditation "PSVA de firma remota acreditado ante el INDECOPI" --service-reference "Res. 000-2025/DGI-INDECOPI" \
  --transaction factura/F001-123 --allow factura --allow constancia \
  --audit-log /var/log/firma/auditoria.jsonl
```

| Option | Meaning |
|---|---|
| `--format pdf\|xml\|cms` | The format of the signature; by default, by the file's extension |
| `--detached` | For CMS, leaves the content out of the signature |
| `--pkcs11-lib`, `--pkcs11-token`, `--pkcs11-key`, `--pin` | The cryptographic module, the key and the PIN (`env:NAME` reads it from an environment variable) |
| `--module-…` | The declared module and its certification |
| `--csc-url`, `--csc-credential`, `--pin` | The remote signing service (Cloud Signature Consortium API v2), the credential and its PIN, instead of the module |
| `--csc-token`, or `--csc-client-id` and `--csc-client-secret` | How the agent authenticates to the service (`env:NAME` reads the secret from an environment variable) |
| `--service-…` | The declared service: provider, the name it reports about itself, accreditation and its reference |
| `--chain file` | A certificate of an issuing CA (PEM or DER), when the module or the service holds the signing certificate alone; repeatable. Without it, a missing issuer is downloaded from the address the certificate names (AIA) |
| `--transaction type/id` | The transaction the signature is for |
| `--allow type` | The kinds of transaction this agent is allowed |
| `--audit-log` | The audit trail of the signatures |
| `--tsa`, `--tsa-cert` | The time-stamp authority and its certificate |
| `--tsl`, `--tsl-signer`, `--trust-root` | Another trusted list, or installed roots, instead of INDECOPI's list |
| `--contingency`, `--contingency-until` | An approved contingency and its validity |

Result: `✓ Signed`, with the signer, the level (B-B without a time-stamp, B-LT with one), the transaction, the policy,
the module and how it protects the key (or the remote signing service and its credential). Exit code 0.

There is no option to sign with a PKCS#12 (PFX) file: it is outside the scope of the accreditation (administration
manual, section 3.3). An option the command does not have is an error, not ignored.

When the operation is refused, the message gives the reason and the exit code is not 0:

| Message | What to do |
|---|---|
| `Refused (KeyNotInModule)` | The key is extractable or not sensitive: use a key generated in the module as not extractable |
| `Refused (ModuleMismatch)` | The token is not the declared one: check `--module-manufacturer` and `--module-model` with `simplesign pkcs11 list` |
| `Refused (RemoteServiceMismatch)` | The service is not the declared one: check `--service-name` with `simplesign csc list` |
| `Refused (RemoteAuthorizationNotUnattended)` | The credential needs a person to authorize it: use a seal credential of the organization |
| `Refused (TransactionNotAllowed)` | The kind of transaction is not in `--allow` |
| `Refused (ContingencyExpired)` | The contingency's validity is over: remove `--contingency` |
| `Error (CertificateRevoked)` | The certificate or one of its chain is revoked: it cannot sign |
| `Error (RevocationStatusUnknown)` | Neither OCSP nor the CRL could be reached: check the outbound network access |
| `Error (CertificateExpired)` | The certificate expired |
| `Error (KeyUsageNotPermitted)` | The certificate lacks the nonRepudiation bit |
| `Error (UntrustedRoot)` | The root CA is not in the trusted list, or an issuing CA's certificate is missing: the message says which. Load it into the module or give it with `--chain` |
| `Error (TimestampUntrusted)` | The token does not come from the configured authority, or the authority is not trusted |
| `Error (TimestampInvalid)` | The token received is not valid: its signature does not verify or it is not over what was sent |
| `Error (TimestampCertificateRevoked)` | The time-stamp authority's certificate is revoked |

## Verifying a received document

```bash
simplesign iofe verify recibido.pdf --sender 20123456789 --contact mesa@entidad.pe --reference MP-2026-001 \
  --audit-log /var/log/firma/verificacion.jsonl --notice comunicado.txt \
  --html-report informe.html --etsi-report informe.xml
```

**Every** signature of the document is verified. The document is accepted (exit code 0) only when it has signatures
and all are valid. Otherwise it is rejected (code 1) and the notice to the sender is written to `--notice`, with the
reason of each signature that is not valid.

`--detached file` gives the signed content of a detached CMS or XML signature.

## Viewer (Req. 18, 28)

```bash
simplesign iofe view factura-firmada.pdf --output visor.html
```

The page, in Spanish, shows for each signature: the integrity of the document, the date and time of the signature
(and the one the time-stamp proves), the public key and the certificate's data (subject, issuer, serial number,
validity, key usage, fingerprint), the time-stamps and the revocation data used, the policy applied, and the errors
and warnings.

## Checking the audit records

```bash
simplesign audit verify /var/log/firma/auditoria.jsonl
```

`✓ Intact` says the chain holds; `✗ Broken at line N`, that line N was changed, removed or inserted after it was
written.
