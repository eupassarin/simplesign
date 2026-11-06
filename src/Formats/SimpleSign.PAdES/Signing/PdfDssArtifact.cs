namespace SimpleSign.PAdES.Signing;

/// <summary>
/// An extra stream stored in the Document Security Store with the long-term validation data:
/// listed in the DSS array <see cref="DssKey"/> and referenced from the signature's VRI
/// dictionary as <see cref="VriKey"/>. Used for profiles that keep more than certificates and
/// revocation data in the DSS, such as the ICP-Brasil PAdES policies (PBAD_PolicyArtifacts…).
/// </summary>
/// <param name="DssKey">Name of the DSS array (a PDF name, without the slash).</param>
/// <param name="VriKey">Name of the VRI entry pointing to this stream.</param>
/// <param name="Content">The bytes of the stream (stored Flate-compressed).</param>
public sealed record PdfDssArtifact(string DssKey, string VriKey, ReadOnlyMemory<byte> Content)
{
    private static readonly string[] Reserved = ["Type", "VRI", "Certs", "OCSPs", "CRLs", "Cert", "OCSP", "CRL", "TU", "TS"];

    /// <summary>Checks that both keys are plain PDF names that do not clash with standard DSS/VRI entries.</summary>
    /// <exception cref="ArgumentException">A key is empty, has delimiters or is reserved.</exception>
    internal void Validate()
    {
        Check(DssKey, nameof(DssKey));
        Check(VriKey, nameof(VriKey));
        if (Content.IsEmpty)
        {
            throw new ArgumentException("A DSS artifact must have content.", nameof(Content));
        }
    }

    private static void Check(string key, string name)
    {
        if (string.IsNullOrEmpty(key) || !key.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '.' or '-')
            || Reserved.Contains(key, StringComparer.Ordinal))
        {
            throw new ArgumentException($"'{key}' is not a usable DSS/VRI key: use a PDF name of letters, digits, '_', '.' or '-', other than the standard entries.", name);
        }
    }
}
