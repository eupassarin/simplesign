using SimpleSign.Core.Extensions;
using SimpleSign.Core.Policies;

namespace SimpleSign.XAdES.TrustedLists;

/// <summary>
/// A trust profile whose trust is one trusted list (ETSI TS 119 612): any country's or organization's, given its
/// location and the certificate it is signed with. The policies are SimpleSign's default ones and the operating
/// system's roots are not trusted: the list alone says who is.
/// <para>
/// It gives trust, not a legal level: a signature that validates under it chains to a service of the list, and nothing
/// says what the signature is in that country's law (for the EU, see the eIDAS package and its qualifier).
/// </para>
/// </summary>
/// <example>
/// <code>
/// var profile = await TrustedListProfile.LoadAsync(new TrustedListSourceOptions
/// {
///     Location = new Uri("https://example.test/tsl.xml"),
///     List = new TrustedListOptions { SignerCertificates = [operatorCertificate] },
/// });
/// var results = await new PdfSignatureValidator(new ValidationOptions { Profile = profile }).ValidateAsync(signed);
/// </code>
/// </example>
public static class TrustedListProfile
{
    /// <summary>The name of a profile made without one, as the CLI's <c>--profile</c> takes it.</summary>
    public const string Name = "tsl";

    /// <summary>The profile over a list already read (a <see cref="TrustedList"/>, a <see cref="TrustedListSource"/>, a <see cref="TrustedListSet"/>).</summary>
    /// <param name="list">The list: the profile's only trust anchors.</param>
    /// <param name="name">The profile's short name; <see cref="Name"/> when null.</param>
    /// <param name="title">The name shown to people; the list's display name when null.</param>
    /// <returns>The profile.</returns>
    public static TrustProfile Create(ITrustAnchorProvider list, string? name = null, string? title = null)
    {
        ArgumentNullException.ThrowIfNull(list);
        return new TrustProfile(name ?? Name, title ?? list.DisplayName, SigningPolicy.Default, ValidationPolicy.Default, [list], []);
    }

    /// <summary>Reads the list (kept current: see <see cref="TrustedListSource"/>) and creates the profile.</summary>
    /// <param name="options">Where the list is and how it is read.</param>
    /// <param name="name">The profile's short name; <see cref="Name"/> when null.</param>
    /// <param name="title">The name shown to people; the list's display name when null.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The profile.</returns>
    public static async Task<TrustProfile> LoadAsync(
        TrustedListSourceOptions options, string? name = null, string? title = null, CancellationToken cancellationToken = default) =>
        Create(await TrustedListSource.LoadAsync(options, cancellationToken).ConfigureAwait(false), name, title);
}
