using SimpleSign.Core.Extensions;

namespace SimpleSign.Adobe.Aatl;

/// <summary>
/// The AATL trust profile: the anchors of the Adobe Approved Trust List (<see cref="AatlExtension"/>) and the
/// <see cref="AatlPolicies"/>, under the name <c>aatl</c>. The operating system's roots are not trusted. A signature
/// whose chain is trusted under it is one Acrobat's AATL trusts; nothing says what it is in a country's law.
/// </summary>
/// <example>
/// <code>
/// var aatl = await AatlProfile.LoadAsync();   // Adobe's list, checked against the bundled Adobe root
/// var results = await new PdfSignatureValidator(new ValidationOptions { Profile = aatl }).ValidateAsync(signed);
/// // Another framework's policies, trusting the AATL too:
/// var both = IcpBrasilProfile.Create().WithTrustFrom(aatl);
/// </code>
/// </example>
public static class AatlProfile
{
    /// <summary>The profile's name, as the CLI's <c>--profile</c> takes it.</summary>
    public const string Name = "aatl";

    /// <summary>The name shown to people.</summary>
    public const string Title = "Adobe Approved Trust List (AATL)";

    /// <summary>The profile over an extension already loaded.</summary>
    /// <param name="extension">The AATL extension.</param>
    /// <returns>The profile.</returns>
    public static TrustProfile Create(AatlExtension extension) =>
        TrustProfile.FromExtension(Name, Title, AatlPolicies.Signing, AatlPolicies.Validation, extension);

    /// <summary>Downloads the list (kept current, see <see cref="AatlSource"/>) and creates the profile.</summary>
    /// <param name="options">Where the list is and how it is read; null for Adobe's, with the bundled root.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The profile.</returns>
    public static async Task<TrustProfile> LoadAsync(AatlOptions? options = null, CancellationToken cancellationToken = default) =>
        Create(await AatlExtension.LoadAsync(options, cancellationToken).ConfigureAwait(false));
}
