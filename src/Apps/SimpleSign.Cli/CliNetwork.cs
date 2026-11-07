using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Http;

namespace SimpleSign.Cli;

/// <summary>
/// The network the CLI uses for TSA, CRL, OCSP and AIA requests. By default the library's own (the
/// SSRF guard refuses localhost and private addresses). Three options, accepted by every command
/// and read before the command line is parsed, open it to a local test environment such as the
/// SimpleSign Sandbox:
/// <list type="bullet">
/// <item><c>--allow-origin URL</c> (repeatable; <c>SIMPLESIGN_ALLOW_ORIGINS</c>, comma-separated): a loopback
/// origin the requests may reach (<see cref="OutboundHttpPolicy.LoopbackOrigins"/>);</item>
/// <item><c>--allow-ldap</c> (<c>SIMPLESIGN_ALLOW_LDAP=true</c>): CRLs over LDAP;</item>
/// <item><c>--tls-trust PEM</c> (<c>SIMPLESIGN_TLS_TRUST</c>): a root (and its intermediates) accepted for HTTPS, next to the system's.</item>
/// </list>
/// </summary>
internal static class CliNetwork
{
    internal const string AllowOrigin = "--allow-origin";
    internal const string AllowLdap = "--allow-ldap";
    internal const string TlsTrust = "--tls-trust";

    /// <summary>The provider of the run: the default one, or the one the options built.</summary>
    public static IHttpClientProvider Provider { get; private set; } = DefaultHttpClientProvider.Instance;

    /// <summary>Whether the options changed the network (the provider is not the default one).</summary>
    public static bool IsConfigured { get; private set; }

    /// <summary>The settings read from the command line and the environment.</summary>
    internal sealed record Settings(IReadOnlyList<Uri> Origins, bool Ldap, string? TlsTrustPath)
    {
        public bool IsEmpty => Origins.Count == 0 && !Ldap && TlsTrustPath is null;
    }

    /// <summary>
    /// Reads the network options out of <paramref name="args"/> (and the environment), sets
    /// <see cref="Provider"/>, and returns the arguments without them for the command parser.
    /// </summary>
    /// <exception cref="ArgumentException">An option has no value, an origin is not a loopback origin, or the PEM cannot be read.</exception>
    public static string[] Configure(string[] args, Func<string, string?>? environment = null)
    {
        var (settings, rest) = Parse(args, environment ?? Environment.GetEnvironmentVariable);
        if (!settings.IsEmpty)
        {
            Provider = Build(settings);
            IsConfigured = true;
        }

        return rest;
    }

    /// <summary>Splits the network options from the other arguments.</summary>
    internal static (Settings Settings, string[] Remaining) Parse(string[] args, Func<string, string?> environment)
    {
        ArgumentNullException.ThrowIfNull(args);
        var origins = new List<Uri>();
        bool ldap = string.Equals(environment("SIMPLESIGN_ALLOW_LDAP"), "true", StringComparison.OrdinalIgnoreCase);
        string? tlsTrust = environment("SIMPLESIGN_TLS_TRUST") is { Length: > 0 } fromEnvironment ? fromEnvironment : null;
        if (environment("SIMPLESIGN_ALLOW_ORIGINS") is { Length: > 0 } list)
        {
            origins.AddRange(list.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(Origin));
        }

        var rest = new List<string>(args.Length);
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (arg == "--")
            {
                rest.AddRange(args[i..]);
                break;
            }

            if (arg == AllowLdap)
            {
                ldap = true;
            }
            else if (Value(args, ref i, AllowOrigin) is { } origin)
            {
                origins.Add(Origin(origin));
            }
            else if (Value(args, ref i, TlsTrust) is { } pem)
            {
                tlsTrust = pem;
            }
            else
            {
                rest.Add(arg);
            }
        }

        return (new Settings(origins, ldap, tlsTrust), [.. rest]);
    }

    /// <summary>The value of <c>--name VALUE</c> or <c>--name=VALUE</c> at <paramref name="i"/>, or null when it is another argument.</summary>
    private static string? Value(string[] args, ref int i, string name)
    {
        if (args[i].StartsWith(name + "=", StringComparison.Ordinal))
        {
            return args[i][(name.Length + 1)..];
        }

        if (args[i] != name)
        {
            return null;
        }

        if (i + 1 >= args.Length)
        {
            throw new ArgumentException($"{name} needs a value.");
        }

        return args[++i];
    }

    private static Uri Origin(string value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri) ? uri : throw new ArgumentException($"{AllowOrigin}: '{value}' is not an absolute URL.");

    /// <summary>The provider for <paramref name="settings"/>.</summary>
    internal static SingleClientProvider Build(Settings settings)
    {
        X509Certificate2Collection? roots = null;
        if (settings.TlsTrustPath is { } path)
        {
            roots = [];
            try
            {
                roots.ImportFromPemFile(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException)
            {
                throw new ArgumentException($"{TlsTrust}: cannot read '{path}': {ex.Message}", ex);
            }

            if (roots.Count == 0)
            {
                throw new ArgumentException($"{TlsTrust}: '{path}' has no PEM certificate.");
            }
        }

        // The handler and the client live as long as the process (one CLI command): not disposed.
#pragma warning disable CA2000
        var handler = new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.FromMinutes(5) };
        if (roots is not null)
        {
            handler.SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, certificate, chain, errors) => AcceptServer(certificate, chain, errors, roots),
            };
        }

        OutboundHttpPolicy policy;
        try
        {
            policy = new OutboundHttpPolicy { LoopbackOrigins = settings.Origins, AllowLdap = settings.Ldap };
        }
        catch (ArgumentException ex)
        {
            throw new ArgumentException($"{AllowOrigin}: {ex.Message}", ex);
        }

        return new SingleClientProvider(new HttpClient(handler) { Timeout = ResilientHttp.DefaultChainRetrievalTimeout * 2 })
        {
            OutboundPolicy = policy,
        };
#pragma warning restore CA2000
    }

    /// <summary>
    /// A server certificate trusted by the system, or one that chains to a root given with <c>--tls-trust</c>
    /// (the PEM may also hold intermediates, such as the Sandbox's <c>/chain.pem</c>).
    /// </summary>
    internal static bool AcceptServer(X509Certificate? certificate, X509Chain? serverChain, SslPolicyErrors errors, X509Certificate2Collection trusted)
    {
        if (errors == SslPolicyErrors.None)
        {
            return true;
        }

        if (certificate is null || errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
        {
            return false;
        }

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        foreach (var candidate in trusted)
        {
            if (candidate.SubjectName.RawData.AsSpan().SequenceEqual(candidate.IssuerName.RawData))
            {
                chain.ChainPolicy.CustomTrustStore.Add(candidate);
            }
            else
            {
                chain.ChainPolicy.ExtraStore.Add(candidate);
            }
        }

        if (serverChain is not null)
        {
            foreach (var element in serverChain.ChainElements)
            {
                chain.ChainPolicy.ExtraStore.Add(element.Certificate);
            }
        }

        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        using var leaf = X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
        return chain.Build(leaf);
    }
}
