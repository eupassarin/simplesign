using SimpleSign.Core.Policies;

namespace SimpleSign.Core.Extensions;

/// <summary>
/// A trust profile: under one name, what a trust framework asks of a signature (its signing and validation policies)
/// and whom it trusts (its trust anchor providers, its chain validation). Each trust framework package gives its own
/// (<c>IofeProfile</c>, <c>IcpBrasilProfile</c>, <c>GovBrProfile</c>); pass one to a signer with <c>WithProfile</c> and to a
/// validator with <see cref="Validation.ValidationOptions.Profile"/>.
/// </summary>
/// <param name="Name">The short name (<c>iofe</c>, <c>icp-brasil</c>, <c>gov-br</c>), as the CLI's <c>--profile</c> takes it.</param>
/// <param name="Title">The name shown to people (<c>Peru (IOFE)</c>).</param>
/// <param name="SigningPolicy">The checks made before signing; null when signatures of this framework are not made here (Gov.br).</param>
/// <param name="ValidationPolicy">The validation policy.</param>
/// <param name="TrustAnchorProviders">Whom the framework trusts: its roots, its trusted list (with its services and history).</param>
/// <param name="ChainValidationProviders">Its checks of the signer's chain (certificate type, national IDs); empty for none.</param>
/// <example>
/// <code>
/// var iofe = await IofeProfile.LoadAsync();
/// await PadesSigner.Document(pdf).WithCertificate(cert).WithProfile(iofe).SignAsync();
/// var results = await new PdfSignatureValidator(new ValidationOptions { Profile = iofe }).ValidateAsync(signed);
/// </code>
/// </example>
public sealed record TrustProfile(
    string Name,
    string Title,
    SigningPolicy? SigningPolicy,
    ValidationPolicy ValidationPolicy,
    IReadOnlyList<ITrustAnchorProvider> TrustAnchorProviders,
    IReadOnlyList<IChainValidationProvider> ChainValidationProviders) : ICountryExtension
{
    /// <summary>The profile without a framework: SimpleSign's default policies, no anchors of its own (the system's roots).</summary>
    public static TrustProfile Default { get; } = new("default", "SimpleSign default", Policies.SigningPolicy.Default, Policies.ValidationPolicy.Default, [], []);

    /// <summary>
    /// The qualifiers that say the qualification of a validated signature under the framework (the eIDAS profile's);
    /// empty for none. <see cref="WithTrustFrom"/> does not add the others': they add trust only.
    /// </summary>
    public IReadOnlyList<ISignatureQualifier> SignatureQualifiers { get; init; } = [];

    /// <summary>Whether signatures are made under this profile (it has a signing policy).</summary>
    public bool CanSign => SigningPolicy is not null;

    /// <inheritdoc />
    string ICountryExtension.RegionCode => Name;

    /// <inheritdoc />
    string ICountryExtension.DisplayName => Title;

    /// <summary>A profile whose trust is a country extension's (its anchors and its chain validation).</summary>
    /// <param name="name">The short name.</param>
    /// <param name="title">The name shown to people.</param>
    /// <param name="signing">The signing policy; null when the framework's signatures are not made here.</param>
    /// <param name="validation">The validation policy.</param>
    /// <param name="extension">The country extension.</param>
    /// <returns>The profile.</returns>
    public static TrustProfile FromExtension(string name, string title, SigningPolicy? signing, ValidationPolicy validation, ICountryExtension extension)
    {
        ArgumentNullException.ThrowIfNull(extension);
        return new(name, title, signing, validation, extension.TrustAnchorProviders, extension.ChainValidationProviders)
        {
            SignatureQualifiers = extension.SignatureQualifiers,
        };
    }

    /// <summary>
    /// This profile with the trust of <paramref name="others"/> added (their anchors and chain validation); the policies
    /// stay this profile's. For example ICP-Brasil's policies, trusting ICP-Brasil and Gov.br.
    /// </summary>
    /// <param name="others">The profiles whose trust is added.</param>
    /// <returns>The combined profile.</returns>
    public TrustProfile WithTrustFrom(params TrustProfile[] others)
    {
        ArgumentNullException.ThrowIfNull(others);
        return this with
        {
            TrustAnchorProviders = [.. TrustAnchorProviders, .. others.SelectMany(o => o.TrustAnchorProviders)],
            ChainValidationProviders = [.. ChainValidationProviders, .. others.SelectMany(o => o.ChainValidationProviders)],
        };
    }

    /// <summary>The signing policy, or the error of a profile that does not sign.</summary>
    /// <exception cref="ArgumentException">The profile does not sign.</exception>
    internal SigningPolicy RequireSigningPolicy() =>
        SigningPolicy ?? throw new ArgumentException($"Signatures of the {Title} profile are not made here (it validates only).", "profile");

    /// <summary>The roots of the profile's providers.</summary>
    internal IReadOnlyList<System.Security.Cryptography.X509Certificates.X509Certificate2> Anchors() =>
        [.. TrustAnchorProviders.SelectMany(p => p.GetTrustAnchors())];
}
