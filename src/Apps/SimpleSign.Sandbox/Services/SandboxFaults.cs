namespace SimpleSign.Sandbox.Services;

/// <summary>What the TSA does with a request.</summary>
public enum TsaFault
{
    /// <summary>Answers normally.</summary>
    None,

    /// <summary>HTTP 503: the TSA is down.</summary>
    Down,

    /// <summary>Answers after <see cref="SandboxFaults.TsaDelayMs"/>.</summary>
    Slow,

    /// <summary>Answers with a token whose bytes were changed.</summary>
    InvalidToken,

    /// <summary>Answers with a token signed by a TSA outside every trust anchor.</summary>
    Untrusted,
}

/// <summary>What the CRL server (HTTP, HTTPS and LDAP) does with a request.</summary>
public enum CrlFault
{
    /// <summary>Serves the current CRLs.</summary>
    None,

    /// <summary>HTTP 503 (LDAP: busy): the CRL server is down.</summary>
    Down,

    /// <summary>Answers after <see cref="SandboxFaults.CrlDelayMs"/>.</summary>
    Slow,

    /// <summary>Serves CRLs whose nextUpdate has passed.</summary>
    Expired,

    /// <summary>Serves CRLs with the issuer's name but signed by another key.</summary>
    WrongKey,

    /// <summary>
    /// Serves the CRL published before the last revocation, still within its validity: the
    /// copy a client cached before the certificate was revoked.
    /// </summary>
    Stale,
}

/// <summary>What the OCSP responder does with a request.</summary>
public enum OcspFault
{
    /// <summary>Answers with the current status.</summary>
    None,

    /// <summary>HTTP 503: the responder is down.</summary>
    Down,

    /// <summary>Answers after <see cref="SandboxFaults.OcspDelayMs"/>.</summary>
    Slow,

    /// <summary>Answers tryLater (responseStatus 3).</summary>
    TryLater,

    /// <summary>Answers with a response whose nextUpdate has passed.</summary>
    Expired,

    /// <summary>Answers with a response signed by a responder the CA never authorized.</summary>
    Unauthorized,

    /// <summary>Answers unknown for every certificate.</summary>
    Unknown,
}

/// <summary>Who signs the OCSP responses of the intermediate CA.</summary>
public enum OcspSigner
{
    /// <summary>The CA itself.</summary>
    Issuer,

    /// <summary>A delegated responder certificate (EKU OCSPSigning, id-pkix-ocsp-nocheck) issued by the CA.</summary>
    Delegated,
}

/// <summary>What the trusted list (/tl/tl.xml) looks like.</summary>
public enum TlFault
{
    /// <summary>A current list, signed by the operator its LOTL pointer names.</summary>
    None,

    /// <summary>A list whose NextUpdate has passed.</summary>
    Expired,

    /// <summary>A list signed by a certificate the LOTL pointer does not name.</summary>
    WrongSigner,

    /// <summary>A list changed after it was signed: its signature no longer verifies.</summary>
    Tampered,
}

/// <summary>Failures switched on, to see how a client reacts. Kept with the environment.</summary>
public sealed record SandboxFaults(
    TsaFault Tsa = TsaFault.None,
    int TsaDelayMs = 3000,
    CrlFault Crl = CrlFault.None,
    int CrlDelayMs = 3000,
    OcspFault Ocsp = OcspFault.None,
    int OcspDelayMs = 3000,
    OcspSigner OcspSigner = OcspSigner.Issuer,
    TlFault TrustedList = TlFault.None)
{
    /// <summary>Whether any failure is on.</summary>
    public bool Any => Tsa != TsaFault.None || Crl != CrlFault.None || Ocsp != OcspFault.None || TrustedList != TlFault.None;

    /// <summary>The same failures with the delays kept within 0–60 s.</summary>
    public SandboxFaults Clamped() => this with
    {
        TsaDelayMs = Math.Clamp(TsaDelayMs, 0, 60_000),
        CrlDelayMs = Math.Clamp(CrlDelayMs, 0, 60_000),
        OcspDelayMs = Math.Clamp(OcspDelayMs, 0, 60_000),
    };
}
