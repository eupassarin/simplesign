# ADR 0021: Signing Policy, LDAP CRLs and the Revocation Cache

**Status:** Accepted

**Context:**
Signature software is expected to make checks the library did not make:
- **Before signing**, only the dates of the signing certificate were checked. The chain, the key usage, the key
  size and revocation were not, so a signer could produce a signature that every validator would reject.
- **CRL distribution points** were followed over HTTP(S) only. Some CAs publish `ldap://` locations, sometimes as
  the only one.
- **Online CRLs** downloaded by `CrlClient.CheckCrlAsync` were not checked against their issuer: a CRL that did not
  list the certificate counted as "not revoked" even when its signature was wrong.
- **Each check downloaded the CRLs again.** The only cache was private to the Brazilian chain validators.

**Decision:**
1. **`SigningPolicy`** (Core) runs in every signer before anything is signed (`SignerAcceptance`): validity of every
   certificate of the chain, key usage digitalSignature or nonRepudiation, RSA ≥ 2048 bits, allowed elliptic
   curves, allowed hash algorithms (SHA-2 and SHA-3). `SigningPolicy.Strict` adds the revocation of the whole chain
   and refuses both a revoked certificate and an unknown status. A failure is a `SigningException` with its own
   `SigningErrorReason`. The local checks are on by default; the revocation check needs the network and is opt-in.
2. **`IChainRevocationChecker` / `ChainRevocationChecker`** move from the Brazil package to Core and become public.
   They check every non-root certificate against its issuer with `CrlEvaluator` (signature, issuer name, validity)
   and OCSP. Signers, the Brazilian validators and, later, the format validators share them.
3. **LDAP CRLs** (`LdapCrlClient`): a read-only LDAPv3 client written on `AsnWriter`/`AsnReader` — anonymous bind,
   one base-object search for `certificateRevocationList;binary`, unbind — with a message size limit and a timeout.
   It is used only when the certificate has no HTTP distribution point and `OutboundHttpPolicy.AllowLdap` is set.
   The host goes through the same address checks as HTTP (ADR 0020): the client resolves the host, refuses
   loopback, private and link-local addresses, and connects to the address it checked.
4. **`IRevocationCache` / `InMemoryRevocationCache`**: CRLs are kept until their nextUpdate, capped by the cache
   lifetime. Used by `ChainRevocationChecker` (default 15 minutes) and, when set, by `CrlClient`.
5. **`CrlClient.CheckCrlAsync(cert, issuer, url, ct)`** checks the CRL against the issuer. The overload without the
   issuer can no longer answer "not revoked": without a verified signature it believes only a revocation.
6. **OCSP and caIssuers locations** must be HTTP(S); an `ldap://` entry is skipped for the next one.

**Consequences:**
- A certificate without key usage, an RSA-1024 key or an expired intermediate now fails at signing time.
  `SigningPolicy.Minimal` restores the old behaviour for tests and migrations.
- Strict signing needs the whole chain up to the root, since each certificate is checked against its issuer.
- LDAP is off by default: it is a new outbound protocol and stays an explicit choice of the deployment.
