using SimpleSign.PAdES.Signing;

namespace SimpleSign.PAdES;

/// <summary>Constructs complete field options from concise test fixture data.</summary>
internal static class PadesSignerBuilderTestExtensions
{
    internal static PadesSignerBuilder WithTestFieldOptions(
        this PadesSignerBuilder builder,
        string? signerName = null,
        string? reason = null,
        string? location = null,
        string? contactInfo = null)
    {
        return builder.WithFieldOptions(new SignatureFieldOptions
        {
            SignerName = signerName,
            Reason = reason,
            Location = location,
            ContactInfo = contactInfo
        });
    }
}
