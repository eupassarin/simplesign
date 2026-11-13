# Trust frameworks

The material the TestBench's trust frameworks (Peru, ICP-Brasil, Gov.br on the Sign and Validate pages) use, besides
what the country packages bundle:

| File | What | SHA-256 |
|---|---|---|
| `indecopi-tsl-signer.pem` | The certificate INDECOPI signs Peru's trusted list (`https://iofe.indecopi.gob.pe/TSL/tsl-pe.xml`) with: `CN=TSL Suscriptor, O=INDECOPI`, valid 2024-08-23 to 2027-08-23. A copy of `tests/unit/TrustFrameworks/Peru/Iofe/SimpleSign.Peru.Iofe.Tests/Fixtures/tsl-pe-signer.pem`. | `bc32323c7ba0af62bdef9ca7e7f499bb71eeb4fa092b9017e15acc4d0bf612ed` (of the DER) |

As that folder's README says, the fingerprint was taken from the list itself: confirm it with INDECOPI before a
deployment trusts it. The TestBench is a test tool; when INDECOPI renews the signer, replace both copies.
