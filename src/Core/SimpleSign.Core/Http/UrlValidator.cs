using System.Net;
using System.Net.Sockets;

namespace SimpleSign.Core.Http;

/// <summary>
/// Validates URLs to prevent SSRF (Server-Side Request Forgery) attacks.
/// Blocks requests to localhost, private/reserved IP ranges, and non-HTTP(S) schemes.
/// Resolves hostnames to IP addresses before validation to prevent DNS rebinding.
/// </summary>
internal static class UrlValidator
{
    /// <summary>
    /// Validates that a URL is safe for outbound HTTP requests (CRL, OCSP, AIA, TSA).
    /// Blocks localhost, private IPs, and non-HTTP(S) schemes.
    /// Does NOT resolve hostnames — use <see cref="IsSafeUrlAsync(string, CancellationToken)"/> for DNS rebinding protection.
    /// </summary>
    internal static bool IsSafeUrl(string url) => IsSafeUrl(url, deferLoopback: false);

    /// <summary>
    /// Like <see cref="IsSafeUrl(string)"/>; with <paramref name="deferLoopback"/> a loopback host
    /// passes, because the request is checked again when it is sent, against the policy in force then
    /// (<see cref="OutboundHttpPolicy.LoopbackOrigins"/>).
    /// </summary>
    internal static bool IsSafeUrl(string url, bool deferLoopback)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return false;
        }

        if (!uri.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase) &&
            !uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return (deferLoopback && IsLoopbackHost(uri)) || !IsBlockedHost(uri.Host);
    }

    /// <summary>Whether the URI names this machine: <c>localhost</c> or a loopback address.</summary>
    internal static bool IsLoopbackHost(Uri uri) =>
        string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase)
        || (IPAddress.TryParse(uri.IdnHost.Trim('[', ']'), out var address) && IPAddress.IsLoopback(address));

    /// <summary>
    /// Validates that a URL is safe for outbound HTTP requests with DNS rebinding protection.
    /// Resolves hostnames and validates all resolved IP addresses.
    /// Prefer this overload for async code paths.
    /// </summary>
    internal static Task<bool> IsSafeUrlAsync(string url, CancellationToken ct = default) =>
        IsSafeUrlAsync(url, OutboundHttpPolicy.Default, ct);

    /// <summary>
    /// Validates a URL like <see cref="IsSafeUrlAsync(string, CancellationToken)"/>, letting the hosts in
    /// <see cref="OutboundHttpPolicy.PrivateNetworkHosts"/> resolve to private (RFC 1918) addresses.
    /// </summary>
    internal static Task<bool> IsSafeUrlAsync(string url, OutboundHttpPolicy? policy, CancellationToken ct = default) =>
        IsSafeUrlAsync(url, policy, Dns.GetHostAddressesAsync, ct);

    /// <summary>Overload with an injectable resolver, for tests.</summary>
    internal static async Task<bool> IsSafeUrlAsync(
        string url,
        OutboundHttpPolicy? policy,
        Func<string, CancellationToken, Task<IPAddress[]>> resolve,
        CancellationToken ct = default)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return false;
        }

        if (!uri.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase) &&
            !uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        policy ??= OutboundHttpPolicy.Default;
        if (IsLoopbackHost(uri) && policy.AllowsLoopback(uri))
        {
            return true;
        }

        return !await IsBlockedHostAsync(uri.Host, policy ?? OutboundHttpPolicy.Default, resolve, ct)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Whether a connection to <paramref name="address"/>, resolved from <paramref name="host"/>, is refused
    /// by <paramref name="policy"/>. Used by transports that connect to an address themselves (LDAP, TSA over TCP).
    /// </summary>
    /// <param name="host">The host name from the URL.</param>
    /// <param name="address">The address about to be connected to.</param>
    /// <param name="policy">The outbound policy.</param>
    /// <param name="origin">The scheme, host and port of the target, to match <see cref="OutboundHttpPolicy.LoopbackOrigins"/>.</param>
    internal static bool IsBlockedAddress(string host, IPAddress address, OutboundHttpPolicy policy, Uri? origin = null)
    {
        if (origin is not null && IPAddress.IsLoopback(address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address)
            && IsLoopbackHost(origin) && policy.AllowsLoopback(origin))
        {
            return false;
        }

        return string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
            || (!IPAddress.TryParse(host, out _) && policy.AllowsPrivateAddressesFor(host)
                ? IsLocalOrLinkLocal(address)
                : IsPrivateOrReserved(address));
    }

    private static bool IsBlockedHost(string host)
    {
        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (IPAddress.TryParse(host, out var ip))
        {
            return IsPrivateOrReserved(ip);
        }

        return false;
    }

    private static async Task<bool> IsBlockedHostAsync(
        string host,
        OutboundHttpPolicy policy,
        Func<string, CancellationToken, Task<IPAddress[]>> resolve,
        CancellationToken ct)
    {
        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (IPAddress.TryParse(host, out var ip))
        {
            return IsPrivateOrReserved(ip);
        }

        // Resolve hostname and check all resolved IPs to prevent DNS rebinding
        try
        {
            var addresses = await resolve(host, ct).ConfigureAwait(false);
            bool allowPrivate = policy.AllowsPrivateAddressesFor(host);
            foreach (var address in addresses)
            {
                if (allowPrivate ? IsLocalOrLinkLocal(address) : IsPrivateOrReserved(address))
                {
                    return true;
                }
            }
        }
        catch (SocketException)
        {
            // DNS resolution failed — allow through (HTTP client will handle the connection failure).
            // Blocking here would break offline scenarios and test environments.
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Cancellation requested — rethrow
            throw;
        }

        return false;
    }

    /// <summary>
    /// Addresses refused even for allow-listed hosts: loopback, link-local (cloud metadata) and unspecified.
    /// </summary>
    private static bool IsLocalOrLinkLocal(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6)
        {
            ip = ip.MapToIPv4();
        }

        if (IPAddress.IsLoopback(ip) || ip.IsIPv6LinkLocal ||
            ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any))
        {
            return true;
        }

        byte[] bytes = ip.GetAddressBytes();
        return ip.AddressFamily == AddressFamily.InterNetwork && bytes.Length == 4 &&
            (bytes[0] == 0 || bytes[0] == 127 || (bytes[0] == 169 && bytes[1] == 254));
    }

    private static bool IsPrivateOrReserved(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip))
        {
            return true;
        }

        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6LinkLocal)
            {
                return true;
            }

            // Check IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
            if (ip.IsIPv4MappedToIPv6)
            {
                var mapped = ip.MapToIPv4();
                return IsPrivateOrReserved(mapped);
            }
        }

        byte[] bytes = ip.GetAddressBytes();
        if (ip.AddressFamily == AddressFamily.InterNetwork && bytes.Length == 4)
        {
            // 10.0.0.0/8
            if (bytes[0] == 10)
            {
                return true;
            }

            // 172.16.0.0/12
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
            {
                return true;
            }

            // 192.168.0.0/16
            if (bytes[0] == 192 && bytes[1] == 168)
            {
                return true;
            }

            // 127.0.0.0/8
            if (bytes[0] == 127)
            {
                return true;
            }

            // 169.254.0.0/16 (link-local / cloud metadata)
            if (bytes[0] == 169 && bytes[1] == 254)
            {
                return true;
            }

            // 0.0.0.0/8
            if (bytes[0] == 0)
            {
                return true;
            }
        }

        return false;
    }
}
