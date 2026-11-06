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
    /// Does NOT resolve hostnames — use <see cref="IsSafeUrlAsync"/> for DNS rebinding protection.
    /// </summary>
    internal static bool IsSafeUrl(string url)
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

        return !IsBlockedHost(uri.Host);
    }

    /// <summary>
    /// Validates that a URL is safe for outbound HTTP requests with DNS rebinding protection.
    /// Resolves hostnames and validates all resolved IP addresses.
    /// Prefer this overload for async code paths.
    /// </summary>
    internal static async Task<bool> IsSafeUrlAsync(string url, CancellationToken ct = default)
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

        return !await IsBlockedHostAsync(uri.Host, ct).ConfigureAwait(false);
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

    private static async Task<bool> IsBlockedHostAsync(string host, CancellationToken ct)
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
            var addresses = await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
            foreach (var address in addresses)
            {
                if (IsPrivateOrReserved(address))
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
