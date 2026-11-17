using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;

namespace SimpleSign.Cli.Extensibility;

/// <summary>What the CLI gives a profile to load itself.</summary>
/// <param name="Http">The CLI's HTTP client and outbound policy (<c>--allow-origin</c>, <c>--tls-trust</c>, a proxy).</param>
/// <param name="Sandbox">The running SimpleSign Sandbox of <c>--sandbox URL</c>, whose lists a profile reads instead of the real ones; null without it.</param>
/// <param name="Signing">True when the profile is loaded to sign, false to validate: an expired trusted list is refused for signing and kept for validation, where the policy judges it.</param>
public sealed record CliProfileContext(IHttpClientProvider Http, Uri? Sandbox, bool Signing);

/// <summary>A trust profile of <c>--profile NAME</c>: the row <c>simplesign profiles</c> shows, and how to load it.</summary>
public sealed record CliProfile
{
    /// <summary>The name the option takes (<c>iofe</c>).</summary>
    public required string Name { get; init; }

    /// <summary>What it is for (<c>Peru (IOFE)</c>).</summary>
    public required string Title { get; init; }

    /// <summary>The name of its signing policy, as <c>simplesign profiles</c> shows it.</summary>
    public string SigningPolicy { get; init; } = "default";

    /// <summary>The name of its validation policy, as <c>simplesign profiles</c> shows it.</summary>
    public string ValidationPolicy { get; init; } = "default";

    /// <summary>Whom it trusts, in a sentence.</summary>
    public string Trust { get; init; } = "";

    /// <summary>Why <c>--profile NAME</c> cannot sign; null (the default) when it can.</summary>
    public string? CannotSign { get; init; }

    /// <summary>Loads the profile: its policies and its trust anchors.</summary>
    public required Func<CliProfileContext, CancellationToken, Task<TrustProfile>> LoadAsync { get; init; }
}
