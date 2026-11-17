using SimpleSign.Core.Extensions;

namespace SimpleSign.Brazil.IcpBrasil;

/// <summary>
/// The ICP-Brasil trust profile: <see cref="IcpBrasilPolicies"/> and the AC Raiz roots with the ICP-Brasil chain
/// validation (<see cref="IcpBrasilExtension"/>), under the name <c>icp-brasil</c>.
/// </summary>
/// <example>
/// <code>
/// var icp = IcpBrasilProfile.Create();
/// await PadesSigner.Document(pdf).WithCertificate(cert).WithProfile(icp).SignAsync();
/// </code>
/// </example>
public static class IcpBrasilProfile
{
    /// <summary>The profile's name, as the CLI's <c>--profile</c> takes it.</summary>
    public const string Name = "icp-brasil";

    /// <summary>Creates the profile.</summary>
    /// <param name="options">The extension's HTTP client, logger, extra roots and CRL cache; null for the defaults.</param>
    /// <returns>The profile.</returns>
    public static TrustProfile Create(IcpBrasilExtensionOptions? options = null) =>
        TrustProfile.FromExtension(Name, "ICP-Brasil", IcpBrasilPolicies.Signing, IcpBrasilPolicies.Validation,
            new IcpBrasilExtension(options ?? new IcpBrasilExtensionOptions()));
}
