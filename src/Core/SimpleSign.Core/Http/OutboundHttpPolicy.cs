using System.Net;

namespace SimpleSign.Core.Http;

/// <summary>
/// Rules for the outbound requests SimpleSign makes (OCSP, CRL, AIA, TSA, trust lists), on top of the
/// built-in SSRF guard that refuses hosts resolving to private or reserved addresses.
/// </summary>
/// <remarks>
/// <para>
/// On corporate networks with split DNS, the internal resolver may answer a public CA host with a
/// private address while the request itself leaves through a proxy. The guard then blocks a download
/// that would have worked. List such hosts in <see cref="PrivateNetworkHosts"/> to let them resolve
/// to private (RFC 1918) addresses.
/// </para>
/// <para>
/// The allow-list never lifts these checks: the URL must be <c>http</c> or <c>https</c>;
/// <c>localhost</c> and literal IP addresses in the URL are judged by address only; and a host that
/// resolves to a loopback, link-local (including cloud metadata at <c>169.254.169.254</c>) or
/// unspecified address is always refused.
/// </para>
/// <para>
/// Return the policy from <see cref="IHttpClientProvider.OutboundPolicy"/>, for example through
/// <see cref="SingleClientProvider.OutboundPolicy"/>.
/// </para>
/// </remarks>
public sealed record OutboundHttpPolicy
{
    /// <summary>The default policy: no host may resolve to a private address.</summary>
    public static OutboundHttpPolicy Default { get; } = new();

    /// <summary>
    /// Whether CRLs may be fetched from <c>ldap://</c> and <c>ldaps://</c> distribution points when the
    /// certificate has no HTTP one. The host checks of this policy apply to LDAP hosts too.
    /// Default: <see langword="false"/>.
    /// </summary>
    public bool AllowLdap { get; init; }

    private readonly IReadOnlyList<string> _privateNetworkHosts = [];

    /// <summary>
    /// Host names allowed to resolve to private (RFC 1918) addresses. An entry is either an exact
    /// host name (<c>crl.ca.example</c>) or a <c>*.</c> wildcard that matches any subdomain but not
    /// the domain itself (<c>*.ca.example</c> matches <c>ocsp.ca.example</c>, not <c>ca.example</c>).
    /// Matching ignores case. IP addresses and <c>localhost</c> are not accepted.
    /// </summary>
    /// <exception cref="ArgumentException">An entry is empty, an IP address, <c>localhost</c>, or uses
    /// <c>*</c> anywhere other than a leading <c>*.</c>.</exception>
    public IReadOnlyList<string> PrivateNetworkHosts
    {
        get => _privateNetworkHosts;
        init
        {
            ArgumentNullException.ThrowIfNull(value);
            var hosts = new List<string>(value.Count);
            foreach (string entry in value)
            {
                hosts.Add(Normalize(entry, out string? error)
                    ?? throw new ArgumentException(error, nameof(value)));
            }

            _privateNetworkHosts = hosts.AsReadOnly();
        }
    }

    /// <summary>Whether <paramref name="host"/> is listed in <see cref="PrivateNetworkHosts"/>.</summary>
    internal bool AllowsPrivateAddressesFor(string host)
    {
        string candidate = host.TrimEnd('.');
        foreach (string entry in _privateNetworkHosts)
        {
            if (entry.StartsWith("*.", StringComparison.Ordinal))
            {
                string suffix = entry[1..];
                if (candidate.Length > suffix.Length &&
                    candidate.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            else if (string.Equals(candidate, entry, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static string? Normalize(string entry, out string? error)
    {
        error = null;
        if (string.IsNullOrWhiteSpace(entry))
        {
            error = "A private-network host entry must not be empty.";
            return null;
        }

        string host = entry.Trim().TrimEnd('.');
        string name = host.StartsWith("*.", StringComparison.Ordinal) ? host[2..] : host;
        if (name.Length == 0 || name.Contains('*', StringComparison.Ordinal) ||
            name.Contains('/', StringComparison.Ordinal) || name.Contains(':', StringComparison.Ordinal))
        {
            error = $"'{entry}' is not a host name. Use 'host.example' or '*.example'.";
            return null;
        }

        if (IPAddress.TryParse(name, out _) || string.Equals(name, "localhost", StringComparison.OrdinalIgnoreCase))
        {
            error = $"'{entry}' cannot be allowed: IP addresses and localhost are always judged by address.";
            return null;
        }

        return host;
    }
}
