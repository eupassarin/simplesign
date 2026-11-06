using SimpleSign.Brasil.Signing;
using SimpleSign.Core.Validation;

namespace SimpleSign.Brasil;

/// <summary>The electronic signature levels of Lei 14.063/2020, art. 4.</summary>
public enum Lei14063SignatureLevel
{
    /// <summary>Assinatura eletrônica simples: identifies the signer and associates the data (art. 4, I).</summary>
    Simples,

    /// <summary>
    /// Assinatura eletrônica avançada: a certificate outside ICP-Brasil or another means that
    /// ties the signature to the signer under their exclusive control (art. 4, II) — Gov.br
    /// signatures, or a signature with a SimpleSign advanced-signature manifest.
    /// </summary>
    Avancada,

    /// <summary>Assinatura eletrônica qualificada: an ICP-Brasil signature certificate (art. 4, III).</summary>
    Qualificada,
}

/// <summary>Classifies validated signatures by the levels of Lei 14.063/2020.</summary>
public static class Lei14063
{
    /// <summary>The <see cref="SignatureValidationResult.ChainValidationMetadata"/> key the Brasil providers fill with the level.</summary>
    public const string MetadataKey = "BR.Lei14063";

    /// <summary>
    /// The Lei 14.063 level of a validated signature: qualificada for a trusted ICP-Brasil
    /// signature certificate (A1–A4), avançada for Gov.br or a signature with an advanced-signature
    /// manifest, simples otherwise.
    /// </summary>
    /// <param name="result">A signature validated with the Brasil extension.</param>
    /// <param name="manifestJson">The signature's manifest (<c>SignatureFieldInfo.ManifestJson</c>), if any.</param>
    /// <returns>The level, or <see langword="null"/> when the signature is not valid.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="result"/> is null.</exception>
    public static Lei14063SignatureLevel? Classify(SignatureValidationResult result, ReadOnlySpan<byte> manifestJson = default)
    {
        ArgumentNullException.ThrowIfNull(result);
        if (result.Indication != SignatureIndication.Valid || result.IsDocumentTimestamp)
        {
            return null;
        }

        if (result.ChainValidationMetadata is { } metadata
            && metadata.TryGetValue(MetadataKey, out string? value)
            && Enum.TryParse(value, out Lei14063SignatureLevel level))
        {
            return level;
        }

        return !manifestJson.IsEmpty && SignatureManifest.FromJsonUtf8(manifestJson) is not null
            ? Lei14063SignatureLevel.Avancada
            : Lei14063SignatureLevel.Simples;
    }
}
