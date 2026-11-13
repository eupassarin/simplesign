using System.Text;
using SimpleSign.Core.Policies;
using SimpleSign.Peru.Iofe;
using SimpleSign.TestBench.Documents;

namespace SimpleSign.TestBench.Policies;

/// <summary>A built-in policy offered in the policy fields, kept as a pinned document <c>preset:kind:name</c>.</summary>
/// <param name="Id">The document id the options carry (<c>preset:signing:iofe</c>).</param>
/// <param name="Kind"><c>signing</c> or <c>validation</c>.</param>
/// <param name="Name">The short name (<c>iofe</c>), as the CLI knows it.</param>
/// <param name="Title">The policy's own name.</param>
public sealed record PolicyPreset(string Id, string Kind, string Name, string Title)
{
    /// <summary>The trust profile the preset belongs to (<c>Iofe</c>, <c>IcpBrasil</c>, <c>GovBr</c>); null for the general ones.</summary>
    public string? Framework { get; init; }
}

/// <summary>The built-in signing and validation policies, as the CLI's <c>--signing-policy</c> / <c>--policy</c> names them.</summary>
internal static class PolicyPresets
{
    private static readonly PolicyConstraint Fail = new(ConstraintLevel.Fail);

    /// <summary>The library's default plus the revocation of the whole chain before signing (revoked or unknown refuses).</summary>
    internal static SigningPolicy Strict { get; } = SigningPolicy.Default
        .WithName("SimpleSign default + revocation")
        .With("SigningCertificate/NotRevoked", Fail).With("SigningCertificate/RevocationDataAvailable", Fail)
        .With("CACertificate/NotRevoked", Fail).With("CACertificate/RevocationDataAvailable", Fail);

    /// <summary>The library's default plus a chain that must reach the trust anchors given to the signer (a trusted list, the Sandbox root).</summary>
    internal static SigningPolicy Anchored { get; } = SigningPolicy.Default
        .WithName("SimpleSign default + chain to the trust anchors")
        .With("SigningCertificate/ProspectiveCertificateChain", Fail);

    /// <summary>Only the dates of the signing certificate (tests and migrations).</summary>
    internal static SigningPolicy Minimal { get; } = SigningPolicy.Default
        .WithName("Signing certificate dates only")
        .With("SigningCertificate/KeyUsage", new PolicyConstraint(ConstraintLevel.Ignore))
        .With("CACertificate/NotExpired", new PolicyConstraint(ConstraintLevel.Ignore))
        .With("Cryptographic", new PolicyConstraint(ConstraintLevel.Ignore));

    /// <summary>The library's default validation policy, with time-stamps out of order and an unavailable signature policy failing.</summary>
    internal static ValidationPolicy StrictValidation { get; } = ValidationPolicy.Default
        .WithName("SimpleSign default, strict")
        .With("Timestamp/Coherence", Fail).With("SignatureConstraints/PolicyAvailable", Fail);

    private static readonly (string Kind, string Name, Func<string> Json, string? Title)[] s_all =
    [
        (PolicyViewer.Signing, "strict", () => Strict.ToJson(), Strict.Name),
        (PolicyViewer.Signing, "minimal", () => Minimal.ToJson(), Minimal.Name),
        (PolicyViewer.Signing, "anchored", () => Anchored.ToJson(), Anchored.Name),
        (PolicyViewer.Signing, "iofe", () => IofePolicies.Signing.ToJson(), IofePolicies.Signing.Name),
        (PolicyViewer.Validation, "strict", () => StrictValidation.ToJson(), StrictValidation.Name),
        (PolicyViewer.Validation, "iofe", () => IofePolicies.Validation.ToJson(), IofePolicies.Validation.Name),
        (PolicyViewer.Signing, "icp-brasil", () => Brazil.IcpBrasil.IcpBrasilPolicies.Signing.ToJson(), Brazil.IcpBrasil.IcpBrasilPolicies.Signing.Name),
        (PolicyViewer.Validation, "icp-brasil", () => Brazil.IcpBrasil.IcpBrasilPolicies.Validation.ToJson(), Brazil.IcpBrasil.IcpBrasilPolicies.Validation.Name),
        (PolicyViewer.Validation, "govbr", () => Brazil.GovBr.GovBrPolicies.Validation.ToJson(), Brazil.GovBr.GovBrPolicies.Validation.Name),
    ];

    /// <summary>The presets.</summary>
    public static IReadOnlyList<PolicyPreset> All { get; } =
        [.. s_all.Select(p => new PolicyPreset(Id(p.Kind, p.Name), p.Kind, p.Name, p.Title ?? p.Name) { Framework = FrameworkOf(p.Name) })];

    /// <summary>The trust profile of a preset, by its name: the TestBench shows a profile's presets only while it is on.</summary>
    private static string? FrameworkOf(string name) => name switch
    {
        "iofe" => "Iofe",
        "icp-brasil" => "IcpBrasil",
        "govbr" => "GovBr",
        _ => null,
    };

    /// <summary>The document id of a preset.</summary>
    public static string Id(string kind, string name) => $"preset:{kind}:{name}";

    /// <summary>The JSON of a preset by kind and name, or null when there is none.</summary>
    public static string? Json(string kind, string name) =>
        s_all.FirstOrDefault(p => p.Kind == kind && p.Name == name) is { Json: { } json } ? json() : null;

    /// <summary>Adds every preset to <paramref name="documents"/>, under its id.</summary>
    public static void AddTo(DocumentStore documents)
    {
        foreach (var (kind, name, json, _) in s_all)
        {
            documents.AddFixed(Id(kind, name), $"{kind}-policy-{name}.json", Encoding.UTF8.GetBytes(json()));
        }
    }
}
