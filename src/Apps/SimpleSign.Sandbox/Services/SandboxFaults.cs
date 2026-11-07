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

/// <summary>What the CRL server does with a request.</summary>
public enum CrlFault
{
    /// <summary>Serves the current CRLs.</summary>
    None,

    /// <summary>HTTP 503: the CRL server is down.</summary>
    Down,

    /// <summary>Answers after <see cref="SandboxFaults.CrlDelayMs"/>.</summary>
    Slow,

    /// <summary>Serves CRLs whose nextUpdate has passed.</summary>
    Expired,
}

/// <summary>Failures switched on, to see how a client reacts. Kept with the environment.</summary>
public sealed record SandboxFaults(
    TsaFault Tsa = TsaFault.None,
    int TsaDelayMs = 3000,
    CrlFault Crl = CrlFault.None,
    int CrlDelayMs = 3000)
{
    /// <summary>Whether any failure is on.</summary>
    public bool Any => Tsa != TsaFault.None || Crl != CrlFault.None;

    /// <summary>The same failures with the delays kept within 0–60 s.</summary>
    public SandboxFaults Clamped() => this with
    {
        TsaDelayMs = Math.Clamp(TsaDelayMs, 0, 60_000),
        CrlDelayMs = Math.Clamp(CrlDelayMs, 0, 60_000),
    };
}
