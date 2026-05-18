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
