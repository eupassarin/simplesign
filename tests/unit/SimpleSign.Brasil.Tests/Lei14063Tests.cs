using Shouldly;
using SimpleSign.Brasil.Signing;
using SimpleSign.Core.Validation;

namespace SimpleSign.Brasil.Tests;

/// <summary>Lei 14.063/2020 art. 4 classification of validated signatures.</summary>
[Trait("Category", "Unit")]
public sealed class Lei14063Tests
{
    private static SignatureValidationResult Valid(IReadOnlyDictionary<string, string>? metadata = null) => new()
    {
        IsIntegrityValid = true,
        IsSignatureValid = true,
        IsCertificateChainValid = true,
        IsNotRevoked = true,
        RevocationSource = RevocationSource.None,
        ChainValidationMetadata = metadata,
    };

    [Theory]
    [InlineData("Qualificada", Lei14063SignatureLevel.Qualificada)]
    [InlineData("Avancada", Lei14063SignatureLevel.Avancada)]
    public void Classify_ProviderMetadata_IsUsed(string value, Lei14063SignatureLevel expected) =>
        Lei14063.Classify(Valid(new Dictionary<string, string> { [Lei14063.MetadataKey] = value })).ShouldBe(expected);

    [Fact]
    public void Classify_NoProvider_IsSimples() =>
        Lei14063.Classify(Valid()).ShouldBe(Lei14063SignatureLevel.Simples);

    [Fact]
    public void Classify_WithManifest_IsAvancada()
    {
        var manifest = new SignatureManifest
        {
            Signer = new ManifestSigner { Name = "Fulano", Cpf = "12345678909" },
            Evidence = new ManifestEvidence { AuthMethod = "govbr", Timestamp = DateTimeOffset.UtcNow },
        };

        Lei14063.Classify(Valid(), manifest.ToJsonUtf8()).ShouldBe(Lei14063SignatureLevel.Avancada);
    }

    [Fact]
    public void Classify_InvalidSignature_IsNull()
    {
        var invalid = new SignatureValidationResult { IsIntegrityValid = false };

        Lei14063.Classify(invalid).ShouldBeNull();
    }
}
