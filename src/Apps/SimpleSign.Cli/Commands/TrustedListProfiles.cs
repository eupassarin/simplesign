using System.Security.Cryptography.X509Certificates;
using SimpleSign.Cli.Extensibility;
using SimpleSign.XAdES.TrustedLists;

namespace SimpleSign.Cli.Commands;

/// <summary>
/// The ways the CLI reads a single trusted list (<c>--tsl</c>), by name (<c>--tsl-profile</c>): which services become
/// anchors. <c>default</c> is the CLI's own (the CA and TSA services); the others come from the installed extensions
/// (<see cref="ICliExtension.TrustedListProfiles"/>).
/// </summary>
internal static class TrustedListProfiles
{
    private const string Default = "default";

    private static readonly CliTrustedListProfile s_default = new()
    {
        Name = Default,
        Options = signer => new TrustedListOptions { SignerCertificates = [signer ?? throw new ArgumentNullException(nameof(signer))] },
    };

    private static List<CliTrustedListProfile> s_profiles = [s_default];

    /// <summary>The profile names, for messages.</summary>
    internal static string Names => string.Join(", ", s_profiles.Select(p => p.Name));

    /// <summary>Sets the profiles to <c>default</c> plus those of <paramref name="extensions"/>.</summary>
    internal static void Use(IEnumerable<ICliExtension> extensions)
    {
        List<CliTrustedListProfile> profiles = [s_default];
        foreach (var profile in extensions.SelectMany(e => e.TrustedListProfiles))
        {
            if (!profiles.Exists(p => p.Name.Equals(profile.Name, StringComparison.OrdinalIgnoreCase)))
            {
                profiles.Add(profile);
            }
        }

        s_profiles = profiles;
    }

    /// <summary>Whether <paramref name="profile"/> is known (null is the default).</summary>
    internal static bool IsKnown(string? profile) => Find(profile) is not null;

    /// <summary>The options the list is read with.</summary>
    /// <param name="profile">The profile name; null for the default.</param>
    /// <param name="signer">The certificate the list must be signed with; null only for a profile that brings its own.</param>
    internal static TrustedListOptions Options(string? profile, X509Certificate2? signer) => Find(profile)!.Options(signer);

    /// <summary>Whether the profile knows the certificate the list is signed with, so <c>--tsl-signer</c> may be left out.</summary>
    internal static bool HasBundledSigner(string? profile) => Find(profile)?.HasBundledSigner ?? false;

    /// <summary>Whether, when validating, a list not signed by its operator gives no anchors instead of stopping the command.</summary>
    internal static bool UnverifiableListGivesNoAnchors(string? profile) => Find(profile)?.UnverifiableListGivesNoAnchors ?? false;

    private static CliTrustedListProfile? Find(string? profile) =>
        s_profiles.Find(p => p.Name.Equals(profile ?? Default, StringComparison.OrdinalIgnoreCase));
}
