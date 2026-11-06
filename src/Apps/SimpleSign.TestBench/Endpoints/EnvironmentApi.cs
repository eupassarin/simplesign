using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Brazil.GovBr;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.Core.Signing;

namespace SimpleSign.TestBench.Endpoints;

/// <summary>A trusted root, as the Real environment panel lists it.</summary>
public sealed record TrustedRootView(string Source, string Subject, string NotAfter, string Thumbprint);

/// <summary>A public time-stamping authority the library has a preset for.</summary>
public sealed record PublicTsaView(string Name, string Url, string Api);

/// <summary>What the Real environment has on this machine: the roots validation can trust and the public TSAs.</summary>
public sealed record RealEnvironmentView(
    int SystemRootCount,
    IReadOnlyList<TrustedRootView> BundledRoots,
    IReadOnlyList<PublicTsaView> PublicTsas);

/// <summary>Facts about the real environment (no sandbox): trust and public services.</summary>
internal static class EnvironmentApi
{
    public static void Map(RouteGroupBuilder api) => api.MapGet("/environment/real", Real);

    internal static RealEnvironmentView Real()
    {
        static IEnumerable<TrustedRootView> Roots(string source, IEnumerable<X509Certificate2> roots) => roots
            .Select(r => new TrustedRootView(source, r.Subject, r.NotAfter.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), r.Thumbprint));

        var bundled = Roots("ICP-Brasil", new IcpBrasilExtension().TrustAnchorProviders.SelectMany(p => p.GetTrustAnchors()))
            .Concat(Roots("Gov.br", new GovBrExtension().TrustAnchorProviders.SelectMany(p => p.GetTrustAnchors())))
            .DistinctBy(r => r.Thumbprint)
            .OrderBy(r => r.Source, StringComparer.Ordinal).ThenBy(r => r.Subject, StringComparer.Ordinal)
            .ToList();
        return new RealEnvironmentView(
            SystemRoots(),
            bundled,
            [
                new("DigiCert", TimestampOptions.DigiCert.Endpoint.AbsoluteUri, "TimestampOptions.DigiCert"),
                new("Sectigo", TimestampOptions.Sectigo.Endpoint.AbsoluteUri, "TimestampOptions.Sectigo"),
                new("FreeTSA", TimestampOptions.FreeTsa.Endpoint.AbsoluteUri, "TimestampOptions.FreeTsa"),
            ]);
    }

    /// <summary>How many roots the operating system trusts (the user's and the machine's stores).</summary>
    private static int SystemRoots()
    {
        var thumbprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var location in new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine })
        {
            try
            {
                using var store = new X509Store(StoreName.Root, location);
                store.Open(OpenFlags.ReadOnly);
                foreach (var certificate in store.Certificates)
                {
                    thumbprints.Add(certificate.Thumbprint);
                    certificate.Dispose();
                }
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                // A store that cannot be opened contributes nothing.
            }
        }

        return thumbprints.Count;
    }
}
