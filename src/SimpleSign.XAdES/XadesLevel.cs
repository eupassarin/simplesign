namespace SimpleSign.XAdES;

/// <summary>XAdES conformance level per ETSI EN 319 132-1.</summary>
public enum XadesLevel
{
    /// <summary>Basic signature (signed properties, signer certificate).</summary>
    Basic = 0,

    /// <summary>With a SignatureTimeStamp embedded as an unsigned property.</summary>
    Timestamped = 1,

    /// <summary>With certificate and revocation values (LTV) embedded.</summary>
    LongTerm = 2,

    /// <summary>With archival timestamp for long-term preservation.</summary>
    Archive = 3
}
