# Security configuration (section 5 of the guide)

The configuration that must be in place for the application to meet every requirement. The users of the application
are responsible for applying it and keeping it up to date. (English translation of
[`configuracion-de-seguridad.md`](../configuracion-de-seguridad.md); the Spanish text is the one handed to INDECOPI.)

Most requirements **do not depend on configuration**: the policy that checks the certificate is fixed and the library
offers no parameter to switch it off. What follows is what does depend on whoever installs it.

| # | Configuration | Why |
|---|---|---|
| 1 | Use only `IofeSigningAgent` and `IofeVerificationAgent` (or `simplesign iofe`) for the accredited operations. SimpleSign's general signers (`PadesSigner`, `CadesSigner`, `XadesSigner`) accept policies and keys the accreditation does not cover | Req. 14, 15, 24 |
| 2 | Keep the private key in a cryptographic module certified FIPS 140-2 or Common Criteria EAL 4+, generated in the module and not extractable (`CKA_SENSITIVE` true, `CKA_EXTRACTABLE` false); or in a remote signing service accredited by INDECOPI or with a certified signing device. Do not use PKCS#12 (PFX) files for the accredited operations | Req. 15 |
| 3 | Declare in `ModuleDeclaration` the manufacturer and the model as the driver reports them (`simplesign pkcs11 list`), the certification and the number of its certificate; or in `RemoteServiceDeclaration` the provider, the name the service reports about itself (`simplesign csc list`), its accreditation and the reference of it | Req. 15 |
| 4 | Do not write the PIN, the service token or the client secret in files or on the command line: use an environment variable (`--pin env:NAME`, `--csc-client-secret env:NAME`) or the platform's secret store | Req. 14 |
| 5 | Write the audit records to a volume the application's account can only append to, and copy them to an external system. Check the chain regularly: `simplesign audit verify <file>` | Req. 14, 24 |
| 6 | Define in `Transactions` only the kinds of transaction the agent must sign for | Req. 14 |
| 7 | Allow outbound network access to the CRL distribution points, the OCSP services, the time-stamp authority, INDECOPI's list and, when the key is in a remote signing service, that service's `https` address. For CRLs published over LDAP, enable `AllowLdap` in the outbound policy (`--allow-ldap`) | Req. 11, 21 |
| 8 | Configure the time-stamp authority with its certificate (`IofeTimestampAuthority`), obtained from its provider | Section 4.4 |
| 9 | Declare a contingency (`Contingency`) only under a procedure INDECOPI approved, with its validity, and remove it when it ends | Req. 14, 24 |
| 10 | Keep the system clock synchronized (NTP): the validity of certificates, CRLs and the list is judged against it | Req. 12, 22 |
| 11 | Run the application under a service account without administrator privileges and restrict access to the system that hosts it | Req. 14, 24 |
| 12 | Install the packages from nuget.org and check their signature before deploying them (see the administration manual) | Req. 17, 27 |
