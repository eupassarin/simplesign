using SimpleSign.Core.Http;

namespace SimpleSign.Cli.Extensibility;

/// <summary>What the CLI lends an extension: its network, its way of asking for a PIN and of reading a secret.</summary>
public sealed class CliExtensionContext
{
    private readonly Func<IHttpClientProvider> _http;
    private readonly Func<string?, Task<string?>> _resolvePin;
    private readonly Func<string?, string?> _resolveSecret;

    /// <summary>Creates the context.</summary>
    /// <param name="cliVersion">The version of the CLI.</param>
    /// <param name="httpClientProvider">Gives the CLI's HTTP client provider, read at each use.</param>
    /// <param name="resolvePin">Turns the value of a <c>--pin</c> option into the PIN.</param>
    /// <param name="resolveSecret">Turns the value of an option that accepts <c>env:NAME</c> into the secret.</param>
    public CliExtensionContext(
        Version cliVersion,
        Func<IHttpClientProvider> httpClientProvider,
        Func<string?, Task<string?>> resolvePin,
        Func<string?, string?> resolveSecret)
    {
        ArgumentNullException.ThrowIfNull(cliVersion);
        ArgumentNullException.ThrowIfNull(httpClientProvider);
        ArgumentNullException.ThrowIfNull(resolvePin);
        ArgumentNullException.ThrowIfNull(resolveSecret);
        CliVersion = cliVersion;
        _http = httpClientProvider;
        _resolvePin = resolvePin;
        _resolveSecret = resolveSecret;
    }

    /// <summary>The version of the CLI the extension runs in.</summary>
    public Version CliVersion { get; }

    /// <summary>
    /// The CLI's HTTP client and outbound policy, as <c>--allow-origin</c>, <c>--allow-ldap</c>, <c>--tls-trust</c> and
    /// <c>--sandbox</c> set them. Read it when a command runs, not when the extension is initialized.
    /// </summary>
    public IHttpClientProvider HttpClientProvider => _http();

    /// <summary>
    /// The PIN for the value of a <c>--pin</c> option: the value itself (<c>env:NAME</c> read from the environment),
    /// else a prompt; null when the answer is blank or there is no terminal, which lets a reader with a PIN pad ask for it.
    /// </summary>
    /// <param name="value">The value of the option; null when it was not given.</param>
    /// <returns>The PIN, or null.</returns>
    public Task<string?> ResolvePinAsync(string? value) => _resolvePin(_resolveSecret(value));

    /// <summary>The secret for the value of an option: <c>env:NAME</c> is read from the environment, anything else is the secret.</summary>
    /// <param name="value">The value of the option.</param>
    /// <returns>The secret, or null when the value is null.</returns>
    public string? ResolveSecret(string? value) => _resolveSecret(value);
}
