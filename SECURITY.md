# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in SimpleSign, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please send an email to the maintainers describing the vulnerability. Include:

1. A description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | ✅        |
| 0.1.x   | ❌        |

## Security Considerations

- SimpleSign uses only `System.Security.Cryptography` from the .NET runtime — no third-party cryptography libraries
- All signing operations are performed locally; no data is sent to external services (except TSA requests for timestamping, which send only the document hash — never the document content)
- Private keys are never read or stored by SimpleSign; signing is delegated to the OS certificate store or external signers
- Outbound requests (TSA, OCSP, CRL, AIA) refuse loopback, private and link-local addresses unless a host is listed in `OutboundHttpPolicy.PrivateNetworkHosts`; a service on this machine is reached only when its exact origin is listed in `OutboundHttpPolicy.LoopbackOrigins` (empty by default, for local test environments such as the SimpleSign Sandbox). CRLs over LDAP are off by default (`OutboundHttpPolicy.AllowLdap`) and get the same address checks
- Signing runs `SigningPolicy.Default` unless told otherwise: weak keys (RSA under 2048 bits), obsolete hashes (MD5, SHA-1), certificates without a signing key usage and expired chain certificates are refused. `SigningPolicy.Minimal` turns these checks off and is meant for tests only
- A validation policy or a trust folder can be protected with a detached CMS signature (`ValidationPolicy.LoadSigned`, `DirectoryTrustAnchorProvider` with a manifest signer), so it cannot be changed by anyone without the administrator's key
