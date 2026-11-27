# ADR 0034: Plain XML-DSig in SimpleSign.XAdES, and the Fiscal Layouts on Top of It

**Status:** Accepted.

**Context:**
`SimpleSign.Brazil.Fiscal` (NF-e, CT-e, MDF-e, NFS-e, eSocial, EFD-Reinf) and `SimpleSign.Brazil.IcpBrasil.Xades`
were removed in 0.13.0 (the last version with them is 0.12.0). Bringing them back as they were did not fit what had
changed since:

- The fiscal package did its own XML-DSig: its own canonicalization, its own hashing, and no signing policy. The
  certificate was never checked before signing (chain, revocation, key usage), no audit record was written, and the
  only way to sign with a key held elsewhere was one call to an `IExternalSigner`. Two-phase signing (ADR 0028) had no
  fiscal form, so a server could not prepare an NF-e for an A3 token behind the local agent.
- The CLI references no trust framework (ADR 0030): `simplesign fiscal sign` lived in `SimpleSign.Cli` with
  `InternalsVisibleTo`.
- The Brazilian packages build on the public API of the formats, and what the fiscal signer needs is internal there:
  the session envelope (`DeferredSessionEnvelope`), the canonicalization of an element in its document, the signing
  policy and the audit.
- The SEFAZ layouts mandate RSA-SHA1. SimpleSign refuses SHA-1 in at least six places (the default signing policy,
  `CryptoUtility.ComputeHash`, `CmsSignatureBuilder.GetDigestOid`, the algorithm resolver, the external signers, the
  agent), with no switch to turn it on.
- `brasil sign` could add only to a PDF signer (`CliSignRequest.Configure` takes a `PadesSignerBuilder`), so the CLI
  could sign under an ICP-Brasil policy in PAdES only.

**Decision:**

1. **Plain XML-DSig is a format, in SimpleSign.XAdES.** `XmlDsigSigner` (one call, `SignAllAsync` for a batch),
   `XmlDsigDeferredSigner` (two phases, an HMAC-authenticated session `{"format":"XMLDSig",…}`) and `XmlDsigValidator`
   make and check an enveloped W3C XML Signature 1.0 without qualifying properties: one `Reference` to an element by
   its Id (or `URI=""`), the enveloped-signature and C14N transforms, the signature after the element or at the end of
   the root, the signer certificate in `KeyInfo`. Nothing in it is Brazilian. It goes through the same steps as XAdES:
   the signing policy and trust anchors before signing, `BaselineSigning.SignExternallyAsync` (the raw signature
   verified against the certificate), the audit sink. The deferred builder takes every option of the one-call builder
   (the contract test of ADR 0028). It loads XML with DTDs prohibited and refuses a duplicate Id when signing and when
   validating (signature wrapping).
2. **The fiscal layouts are profiles of that format**, in `SimpleSign.Brazil.Fiscal`
   (`src/Extensions/Brazil/Fiscal`, public API only): `FiscalDocumentProfile.Apply(builder)` sets the element, the
   hash, the placement and the canonicalization; `FiscalXmlSigner.Document` adds the ICP-Brasil anchors and the layout's
   signing policy; `FiscalXmlValidator` adds the ICP-Brasil chain, the CNPJ/CPF and the checks of the layout.
3. **SHA-1 is a rule of a policy, not a switch.** `FiscalPolicies.Sefaz` is the ICP-Brasil signing policy with SHA-1
   accepted as the signature digest (`Cryptographic/AcceptableDigestAlgo`), and the CA certificates keep their SHA-2
   list. The layouts that mandate SHA-1 sign under it; the others under `IcpBrasilPolicies.Signing`. Below the policy,
   SHA-1 is opened for one payload only, an XML-DSig `SignedInfo`: `ExternalSigningDigest` (the PKCS#11, CSC and PSC
   signers) and the agent's `/api/sign` (and only with an `rsa-sha1` SignatureMethod and an RSA key). CMS keeps
   refusing SHA-1 at every step.
4. **`SimpleSign.Brazil.IcpBrasil.Xades` returns as it was** (`WithIcpBrasilPolicy` on both XAdES builders, the rules
   of the XML PAs, the verified `LPA_XAdES.xml` refresh). Its signing and its rules use the public API of
   `SimpleSign.Brazil.IcpBrasil`; the LPA refresh uses three of its internals (download from the ITI repository, the
   ITI signer check, applying a verified LPA), so `InternalsVisibleTo` is granted to that package only.
5. **A pass-through command names the standard command it runs.** `CliSignRequest.Command` (`sign`, `cades sign`,
   `xades sign`, `xmldsig sign`) with `ConfigureCades`, `ConfigureXades` and `ConfigureXmlDsig` beside `Configure`.
   `CliExtensionContext.SignAsync` runs that command, so an extension's command takes every option and credential of it
   (a PFX, the Windows store, a PKCS#11 token, a cloud certificate, `--prepare`) without copying any. The contract stays
   version 1: the members have defaults, and an extension that sets them needs a CLI that has them.
6. **The CLI** gains `simplesign xmldsig sign|validate` (generic), and `deferred complete` completes an XML-DSig
   session. The `brasil` extension adds `brasil fiscal sign --layout …` (on `xmldsig sign`), `brasil fiscal validate`,
   `brasil cades sign` and `brasil xades sign` with `--icp-policy`, and the `fiscal-sefaz` signing policy preset.

**Consequences:**
- The fiscal API is a builder, not the static `Sign(xml, profile, cert)` of 0.12.0: the certificate is checked against
  ICP-Brasil before signing, which refuses test certificates unless the policy says otherwise.
- An A3 token signs an NF-e the same way as a PDF: the server prepares (`FiscalXmlSigner.Deferred`), the agent signs
  the `SignedInfo` and the server completes.
- `XmlDsigValidator` checks the chain through a trust profile's chain validation providers, or else builds it to one of
  the profile's anchors (a root or a CA at any level, as a trusted list names them), downloading from the AIA the issuers
  that KeyInfo, which carries the signer certificate only, lacks. It does not apply a validation policy, so SHA-1
  signatures are not marked by the default policy's SHA-1 cut-off of 2012.
- The TestBench's XML page has a Fiscal XML type next to XAdES: it is a kind of the page (the samples, the profile menu
  and the playbooks are the page's) with its own plan and runner, since the steps of a XAdES plan transform a
  `XadesSignerBuilder`.
- The CAdES and XAdES validators, in `ValidateAsync`, now ask the trust frameworks' chain validation (the profile's,
  and `ValidationOptions.ChainValidationProviders`) for what it reads of the signer: the region, the certificate type,
  the signer's identifier, the `BR.*` metadata with the Lei 14.063 level. They ask without revocation, which they check
  themselves, and the provider's errors are warnings: no CAdES or XAdES verdict changes (in a PDF the provider still
  decides). The loop is `ChainValidationProviderRunner`, shared with PAdES. So `cades validate` and `xades validate`
  show the `brasil` extension's notes as `validate` does for a PDF (`CliSignatureFacts.Format`, `Indication`, `Chain`),
  and for a XAdES signature under an ICP-Brasil XML policy the rules of the PA (`IcpBrasilXadesPolicyValidator`).
