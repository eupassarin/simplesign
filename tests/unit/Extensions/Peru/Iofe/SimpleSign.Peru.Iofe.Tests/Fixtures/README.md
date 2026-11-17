# INDECOPI trusted list fixtures

| File | What | SHA-256 |
|---|---|---|
| `tsl-pe-seq25.xml` | INDECOPI's trusted list as published at `https://iofe.indecopi.gob.pe/TSL/tsl-pe.xml`, downloaded 2026-11-12: sequence 25, issued 2026-11-06, NextUpdate 2027-05-06 (ETSI TS 102 231 v3, 353 115 bytes) | `593191979ff9c0d26d38c42eefa16d86bf8b92cb4c7665f0afa7d57e84526029` |
| `tsl-pe-signer.pem` | The certificate that list is signed with: `CN=TSL Suscriptor, OU=DGI, O=INDECOPI, serialNumber=20133840533, C=PE`, issued by `CN=INDECOPI AAC RAIZ`, valid 2024-08-23 to 2027-08-23 | `bc32323c7ba0af62bdef9ca7e7f499bb71eeb4fa092b9017e15acc4d0bf612ed` (of the DER) |

**The signer's fingerprint is to be confirmed with INDECOPI** (out of band, e.g. by a signed letter or the IOFE
office) before a deployment trusts it. It was taken from the list's own `ds:KeyInfo` on the date above, which proves
nothing by itself: the tests only use it to check that the library verifies INDECOPI's signature format, and the
integration test (`IofeTrustedListIntegrationTests`) checks the list online against this same file — never against a
certificate taken from the download.

When INDECOPI renews the signer (the current one expires 2027-08-23) or publishes a new list, the integration test
fails or reports the new sequence number: download the new list, extract and confirm the new signer, replace both
files and update this table and `IofeRealListTests`.
