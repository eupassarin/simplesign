# Public TSA roots

The roots of the public TSAs the TestBench offers. The TestBench's **Public TSA roots** trust choice
(`TrustChoice.PublicTsas`, on by default) trusts them, and the DSS container (`tools/dss`) mounts this folder,
so both validators reach a trust anchor for these TSAs' timestamps.

| File | Root | SHA-256 | Source |
|---|---|---|---|
| `DigiCert-TrustedRootG4.crt` | DigiCert Trusted Root G4 | `552F7BDCF1A7AF9E6CE672017F4F12ABF77240C78E761AC203D1D9D20AC89988` | operating system roots; `http://timestamp.digicert.com` chains to it |
| `Sectigo-PublicTimeStampingRootR46.crt` | Sectigo Public Time Stamping Root R46 | `4941B001B8A97E961B7817C9D9E960EC4B056BFC915A8C1AABF6EF6B3AC046A5` | operating system roots; `http://timestamp.sectigo.com` chains to it |
| `FreeTSA-RootCA.crt` | Free TSA Root CA (`www.freetsa.org`) | `A6379E7CECC05FAA3CBF076013D745E327BBBAA38C0B9AF22469D4701D18AABC` | `https://freetsa.org/files/cacert.pem` |

DigiCert's and Sectigo's are usually among the operating system's roots too; FreeTSA's never is, and DSS trusts
no operating system roots. One PEM certificate per `.crt` file.
