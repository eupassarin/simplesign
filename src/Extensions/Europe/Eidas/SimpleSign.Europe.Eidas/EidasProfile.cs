using SimpleSign.Core.Extensions;

namespace SimpleSign.Europe.Eidas;

/// <summary>
/// The eIDAS trust profile: the EU trusted lists (<see cref="EidasExtension"/>), the <see cref="EidasPolicies"/> and the
/// <see cref="EidasQualifier"/>, under the name <c>eidas</c>.
/// </summary>
/// <example>
/// <code>
/// var eidas = await EidasProfile.LoadAsync();   // the EU LOTL, checked against the bundled signers
/// await PadesSigner.Document(pdf).WithCertificate(cert).WithProfile(eidas).SignAsync();
/// var results = await new PdfSignatureValidator(new ValidationOptions { Profile = eidas }).ValidateAsync(signed);
/// // results[0].Qualification?.Level: QESig, AdESig-QC…
/// </code>
/// </example>
public static class EidasProfile
{
    /// <summary>The profile's name, as the CLI's <c>--profile</c> takes it.</summary>
    public const string Name = "eidas";

    /// <summary>The profile over an extension already loaded.</summary>
    /// <param name="extension">The eIDAS extension.</param>
    /// <returns>The profile.</returns>
    public static TrustProfile Create(EidasExtension extension) =>
        TrustProfile.FromExtension(Name, "EU (eIDAS)", EidasPolicies.Signing, EidasPolicies.Validation, extension);

    /// <summary>Loads the EU LOTL and its lists (kept current, see <see cref="EidasExtension.LoadRefreshableAsync"/>) and creates the profile.</summary>
    /// <param name="options">Where the LOTL is; null for the EU's, with the bundled signers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The profile.</returns>
    public static async Task<TrustProfile> LoadAsync(EidasExtensionOptions? options = null, CancellationToken cancellationToken = default) =>
        Create(await EidasExtension.LoadRefreshableAsync(options, cancellationToken).ConfigureAwait(false));
}
