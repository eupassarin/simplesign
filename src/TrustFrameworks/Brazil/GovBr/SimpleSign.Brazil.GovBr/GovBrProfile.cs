using SimpleSign.Core.Extensions;

namespace SimpleSign.Brazil.GovBr;

/// <summary>
/// The Gov.br trust profile, for validation: <see cref="GovBrPolicies.Validation"/> and the Gov.br roots with their
/// chain validation (<see cref="GovBrExtension"/>), under the name <c>gov-br</c>. It has no signing policy: Gov.br
/// signatures are made on Gov.br's own service.
/// </summary>
/// <example>
/// <code>
/// var results = await new PdfSignatureValidator(new ValidationOptions { Profile = GovBrProfile.Create() }).ValidateAsync(pdf);
/// </code>
/// </example>
public static class GovBrProfile
{
    /// <summary>The profile's name, as the CLI's <c>--profile</c> takes it.</summary>
    public const string Name = "gov-br";

    /// <summary>Creates the profile.</summary>
    /// <param name="options">The extension's HTTP client, logger and CRL cache; null for the defaults.</param>
    /// <returns>The profile.</returns>
    public static TrustProfile Create(GovBrExtensionOptions? options = null) =>
        TrustProfile.FromExtension(Name, "Gov.br", null, GovBrPolicies.Validation, new GovBrExtension(options ?? new GovBrExtensionOptions()));
}
