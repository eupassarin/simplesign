namespace SimpleSign.CAdES;

/// <summary>Specifies how the original data is carried in a CAdES signature.</summary>
public enum CadesContentType
{
    /// <summary>
    /// Detached: the signature references external data by hash.
    /// The original data is NOT embedded in the CMS SignedData.
    /// Output file extension is typically .p7s.
    /// </summary>
    Detached = 0,

    /// <summary>
    /// Enveloped: the original data is embedded inside the CMS SignedData
    /// as the eContent OCTET STRING in encapContentInfo.
    /// Output file extension is typically .p7m.
    /// </summary>
    Enveloped = 1,
}
