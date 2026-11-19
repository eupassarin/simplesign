← [Back to Standards Conformance](../../conformance.md)

# ETSI Signatures Conformance Checker

The [ETSI Signatures Conformance Checker](https://signatures-conformance-checker.etsi.org) (ETSI Centre for Testing
and Interoperability with the Universitat Politècnica de Catalunya) checks the **structure** of an AdES signature
against the clauses of its ETSI specification. For each signature it reports which of its checks passed or failed.
The checks cover the attributes and properties each baseline level requires or forbids, their encoding and order, the
signing-certificate reference, and the imprints of the time-stamps and archive time-stamps.

It does **not** validate the certificate chain or trust. That is why SimpleSign's synthetic test PKI is enough here;
trust is covered by the validation tests and by the DSS cross-validation (`interop-weekly`).

This folder holds what the checker said about the signatures SimpleSign makes:

| File | What it is |
|---|---|
| [`summary.md`](summary.md) | One row per sample: level, checks passed, failures, warnings, date and commit |
| `results.json` | The same data, read and rewritten by the tests (a partial run updates only its samples) |
| `<sample>/<signature>.xml` | The checker's raw report (`xmlrawoutput.xml`) of each signature in the sample |

The signed samples and the checker's full report (HTML pages, message-imprint traces) are not committed. They are
written to `SIMPLESIGN_ETSI_ARTIFACTS`, or to `etsi-checker/` next to the test assembly.

## The samples

[`EtsiCorpus`](../../../tests/integration/SimpleSign.EtsiChecker.Tests/EtsiCorpus.cs) makes them offline. The
signer, ECDSA key, TSA and CRLs come from `OfflinePki`. Each sample is checked against the baseline profile of its
format.

Before any of them goes to the checker, `EtsiCorpusTests` (a unit test, run in CI) checks each one with SimpleSign
itself. It must reach the level it claims and hold the number of signatures it should, and every signature in it
must be intact and valid for SimpleSign's own validators: the earlier signatures of a PDF signed again, each
co-signer and each counter-signature included. A later signature that broke an earlier one fails there, without an
account at the checker.

| Format | Profile (`selectedSpec`) | Samples |
|---|---|---|
| PAdES | EN 319 142-1 v1.1.1 (`EN31914201v010101`) | B-B, B-T, B-LT, B-LTA; adbe.pkcs7.detached (fails as expected); ECDSA; RSASSA-PSS; visible; certified; B-B augmented to B-LTA; archive renewed; two-phase; **several signatures:** two (RSA, ECDSA), three, certified then signed, two raised together to B-LTA, B-LTA signed again at B-LTA |
| CAdES | EN 319 122-1 v1.1.1 (`EN31912201v010101`) | B-B, B-T, B-LT, B-LTA (enveloping); ECDSA; RSASSA-PSS; B-B augmented to B-LTA; archive renewed; two-phase; **several signatures:** counter-signed, co-signed (two SignerInfos) at B-T and at B-LTA |
| XAdES | EN 319 132-1 (`EN31913201v010101`) | B-B enveloped and enveloping; B-T, B-LT, B-LTA; ECDSA; B-B augmented to B-LTA; archive renewed; two-phase; **several signatures:** counter-signed, two enveloped signatures at B-T and at B-LTA |

Detached CAdES and XAdES are left out. The checker takes a single file and has no field for the detached content,
so it can only report the message digest as wrong.

## Running it

You need an account at the checker (free, register on its site), then:

```bash
SIMPLESIGN_ETSI_USER='…' SIMPLESIGN_ETSI_PASSWORD='…' dotnet test tests/integration/SimpleSign.EtsiChecker.Tests --framework net10.0
```

| Variable | Use |
|---|---|
| `SIMPLESIGN_ETSI_USER`, `SIMPLESIGN_ETSI_PASSWORD` | The account. Without them the checks are skipped. |
| `SIMPLESIGN_REQUIRE_ETSI_CHECKER=true` | Fail instead of skipping when there is no account. |
| `SIMPLESIGN_ETSI_EVIDENCE` | Where the reports go; default: this folder. |
| `SIMPLESIGN_ETSI_ARTIFACTS` | Where the samples and full reports go. |
| `SIMPLESIGN_ETSI_CORPUS` | Write the samples there for an upload by hand (this needs no account: run the `EtsiCorpusTests`). |
| `SIMPLESIGN_ETSI_URL` | Another address for the checker. |

The checker publishes no API. The tests use the one its own web page calls:
- `POST /api/auth/login` returns a bearer token.
- `POST /api/sig/uploadfile` answers with the whole report.

The tests send one file at a time, with a pause between them. If the page changes, `EtsiCheckerClient` is the place
to adapt. It runs on a developer's machine, never in CI, so the account stays out of the repository's secrets.

## When the checker fails a sample

One failure is expected. `pades-b-t-adbe` is signed with `/SubFilter /adbe.pkcs7.detached`, which SimpleSign
writes on request for PDF/A-1 and older validators. EN 319 142-1 allows only `ETSI.CAdES.detached` in a baseline
signature, so this signature holds what B-T requires but is not a baseline signature. SimpleSign says so: the
`ConformanceDetector` reports `CmsOnly` and the signer adds the warning `SubFilterNotBaseline`. The checker must fail
it too. The first run of the checker found that SimpleSign was reporting it as B-T, which was the fault fixed here.

Any other failure is one of two things:
- **A fault of SimpleSign:** fix it, and the next run turns the row green.
- **A fault of the checker:** see its [tracker](https://github.com/lovele0107/signatures-conformance-checker/issues).
  Known open faults include an archive-time-stamp-v3 with another hash algorithm (#27), the PAdES contentTimestamp
  (#43) and XAdES `ds:Object` in the archive imprint (#51). Add the failure to
  [`known-issues.json`](../../../tests/integration/SimpleSign.EtsiChecker.Tests/known-issues.json) as
  `{ "sample", "check", "messageContains", "reason", "link" }`.

  A known issue that stops failing fails the test, so the list never outlives the fault.
