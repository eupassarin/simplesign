using System.Security.Cryptography.X509Certificates;
using SimpleSign.XAdES.TrustedLists;

namespace SimpleSign.Cli.Extensibility;

/// <summary>A way of reading the trusted list of <c>--tsl</c>, chosen with <c>--tsl-profile NAME</c>: which of its services become trust anchors.</summary>
public sealed record CliTrustedListProfile
{
    /// <summary>The name the option takes (<c>iofe</c>).</summary>
    public required string Name { get; init; }

    /// <summary>
    /// The options the list is read with. The argument is the certificate of <c>--tsl-signer</c>, null when it was not
    /// given, which only happens when <see cref="HasBundledSigner"/> is true.
    /// </summary>
    public required Func<X509Certificate2?, TrustedListOptions> Options { get; init; }

    /// <summary>Whether the profile knows the certificate the list is signed with, so <c>--tsl-signer</c> may be left out.</summary>
    public bool HasBundledSigner { get; init; }

    /// <summary>
    /// Whether, when validating, a list that is not signed by its operator gives no anchors (the signatures come out
    /// INDETERMINATE) instead of stopping the command.
    /// </summary>
    public bool UnverifiableListGivesNoAnchors { get; init; }
}
