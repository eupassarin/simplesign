namespace SimpleSign.Brasil.Constants;

/// <summary>
/// Brazilian OID constants (arc 2.16.76.*).
/// </summary>
internal static class BrasilOids
{
    /// <summary>ICP-Brasil SAN: holder data containing CPF at positions 8–18.</summary>
    internal const string IcpBrasilSanHolderData = "2.16.76.1.3.1";

    /// <summary>ICP-Brasil SAN: CNPJ (14 digits).</summary>
    internal const string IcpBrasilSanCnpj = "2.16.76.1.3.3";

    /// <summary>
    /// Signature manifest — JSON-encoded AEA evidence (name, CPF, email, IP, auth method).
    /// OID arc: 2.16.76 (Brazil) / 1.12 (electronic signature extensions) / 1.1 (manifest v1).
    /// </summary>
    internal const string SignatureManifest = "2.16.76.1.12.1.1";
}
