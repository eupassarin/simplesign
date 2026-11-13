using SimpleSign.Core.Extensions;

namespace SimpleSign.Peru.Iofe;

/// <summary>
/// The IOFE trust profile (Peru): the policies of INDECOPI's accreditation guide (<see cref="IofePolicies"/>) and the
/// anchors of INDECOPI's trusted list (<see cref="IofeExtension"/>), under the name <c>iofe</c>.
/// </summary>
/// <example>
/// <code>
/// var iofe = await IofeProfile.LoadAsync();   // INDECOPI's list, checked against the bundled signer
/// await PadesSigner.Document(pdf).WithCertificate(cert).WithProfile(iofe).SignAsync();
/// </code>
/// </example>
public static class IofeProfile
{
    /// <summary>The profile's name, as the CLI's <c>--profile</c> takes it.</summary>
    public const string Name = "iofe";

    /// <summary>The profile over an extension already loaded.</summary>
    /// <param name="extension">The IOFE extension (INDECOPI's list, or another list read the IOFE way).</param>
    /// <returns>The profile.</returns>
    public static TrustProfile Create(IofeExtension extension) =>
        TrustProfile.FromExtension(Name, "Peru (IOFE)", IofePolicies.Signing, IofePolicies.Validation, extension);

    /// <summary>
    /// Downloads INDECOPI's trusted list (by default from <see cref="IofeExtensionOptions.DefaultTrustedListUrl"/>, checked
    /// against <see cref="IofeExtension.IndecopiSigners"/>) and creates the profile. The list is kept current: see
    /// <see cref="IofeExtension.LoadRefreshableAsync"/>.
    /// </summary>
    /// <param name="options">Where the list is and how it is read; null for INDECOPI's, with the bundled signer.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The profile.</returns>
    public static async Task<TrustProfile> LoadAsync(IofeExtensionOptions? options = null, CancellationToken cancellationToken = default) =>
        Create(await IofeExtension.LoadRefreshableAsync(options ?? new IofeExtensionOptions(), cancellationToken).ConfigureAwait(false));
}
