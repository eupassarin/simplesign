using System.Security.Cryptography.X509Certificates;
using SimpleSign.Peru.Iofe;
using SimpleSign.XAdES.TrustedLists;

namespace SimpleSign.Cli.Commands;

/// <summary>
/// The ways the CLI reads a single trusted list (<c>--tsl</c>), by name (<c>--tsl-profile</c>): which services become
/// anchors.
/// </summary>
internal static class TrustedListProfiles
{
    /// <summary>The profile names, for messages and validation.</summary>
    internal const string Names = "default, iofe";

    /// <summary>Whether <paramref name="profile"/> is known (null is the default).</summary>
    internal static bool IsKnown(string? profile) => profile is null || profile.Equals("default", StringComparison.OrdinalIgnoreCase)
        || profile.Equals("iofe", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The options of a profile: <c>default</c>, the CA and TSA services (<see cref="TrustedListOptions"/>); <c>iofe</c>,
    /// INDECOPI's list (<see cref="IofeExtension.DefaultListOptions"/>: the <c>unspecified</c> services too, never a
    /// code-signing certificate).
    /// </summary>
    /// <param name="profile">The profile name; null for the default.</param>
    /// <param name="signer">The certificate the list must be signed with; null with <c>iofe</c> for INDECOPI's bundled one (<see cref="IofeExtension.IndecopiSigners"/>).</param>
    internal static TrustedListOptions Options(string? profile, X509Certificate2? signer)
    {
        if (IsIofe(profile))
        {
            return IofeExtension.DefaultListOptions with { SignerCertificates = signer is null ? IofeExtension.IndecopiSigners : [signer] };
        }

        return new TrustedListOptions { SignerCertificates = [signer ?? throw new ArgumentNullException(nameof(signer))] };
    }

    /// <summary>Whether <paramref name="profile"/> is <c>iofe</c>.</summary>
    internal static bool IsIofe(string? profile) => profile is not null && profile.Equals("iofe", StringComparison.OrdinalIgnoreCase);
}
