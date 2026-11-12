# ADR 0026: Trust Anchors at a Time (Trusted-List Service History)

**Status:** Accepted.

**Context:**
A trusted list (ETSI TS 119 612) gives each trust service a current status with its `StatusStartingTime`, and the
earlier statuses in `ServiceHistory`. SimpleSign read only the current status: a CA whose service was withdrawn
yesterday was not an anchor, even for a signature time-stamped while it was granted. TS 119 615 and EN 319 102-1 say
otherwise: a trust service vouches for what it did while its status was active, so a signature proven to exist before
the withdrawal keeps its trust. The library had no notion of "the anchors at a given time".

**Decision:**
- `TrustedList` parses `StatusStartingTime` and each `ServiceHistoryInstance` (`TrustedListService.StatusStartingTime`,
  `History`, `StatusAt(time)`), and answers `GetTrustAnchors(DateTimeOffset at)`: the anchors of the services whose
  status at that time was active. `GetTrustAnchors()` is unchanged (today's status).
- A new extension point, `ITimedTrustAnchorProvider` (an `ITrustAnchorProvider` with `GetTrustAnchors(at)`),
  implemented by `TrustedList` and `TrustedListSet`.
- `ValidationOptions.TimedTrustAnchors` takes such providers. They are used only when today's anchors do not trust a
  certificate, so no existing validation changes:
  - the TSA of the signature time-stamp is judged with the anchors of the token's genTime (the TSA's service was granted
    when it issued it); the same for content and archive time-stamps in the policy's Timestamp context;
  - the signer's chain is built again with the anchors of the signature's proof of existence (the trusted signature
    time-stamp). When it reaches them, the earlier chain errors are replaced and a warning says the chain reaches the
    anchors of that time, not today's.
- The PAdES, CAdES and XAdES validators apply the same rule (`TimedTrust` in Core). The CLI passes the lists of
  `--tsl` and `--lotl` as timed anchors; the TestBench passes the Sandbox's trusted lists.
- While wiring this, two gaps closed: the CAdES and XAdES validators judged the signature time-stamp's TSA only with
  anchors given to the call, not with `ValidationOptions.TrustedRoots`, so the time-stamp gave no proof of existence;
  and the XAdES time-stamp result lost its genTime.
- Signing is unchanged: before signing, trust is today's (the `ProspectiveCertificateChain` constraint of the signing
  policy).

**Consequences:** a signature time-stamped while its CA's service was granted stays TOTAL_PASSED after the service is
withdrawn, when the validator is given the trusted list as timed anchors. Without a proof of existence (B-B) the
signature is judged with today's anchors. The Sandbox publishes this case (`TlFault.WithdrawnAfterUse`: the root CA's
service withdrawn now, granted before in its history) and the ETSI playbook checks it for PAdES and XAdES (TL-5).
