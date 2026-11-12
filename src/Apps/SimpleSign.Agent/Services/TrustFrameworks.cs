using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Brazil.GovBr;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Signing;

namespace SimpleSign.Agent.Services;

/// <summary>A trust framework the agent knows: a short id for <c>?trust=</c> and its country extension.</summary>
internal sealed record TrustFramework(string Id, Lazy<ICountryExtension> Extension);

/// <summary>
/// The trust frameworks the agent filters certificates by (<c>GET /api/certificates?country=XX</c> or
/// <c>?trust=id</c>): a certificate belongs to one when it chains to one of the framework's trust anchors, with the
/// framework's intermediate certificates. Country-neutral: any <see cref="ICountryExtension"/> can be registered.
/// </summary>
internal sealed class TrustFrameworks(IReadOnlyList<TrustFramework> frameworks)
{
    private const string TrustConstraint = "SigningCertificate/ProspectiveCertificateChain";

    /// <summary>Only the chain to the anchors is asked; revocation stays off (no network while listing).</summary>
    private static readonly SigningPolicy s_chainPolicy = SigningPolicy.Default
        .WithName("Agent certificate filter")
        .With(TrustConstraint, new PolicyConstraint(ConstraintLevel.Fail));

    private readonly ConcurrentDictionary<(string Framework, string Thumbprint), bool> _trusted = new();

    /// <summary>The frameworks of the country packages the agent ships with: ICP-Brasil and Gov.br.</summary>
    public static TrustFrameworks Default { get; } = new(
    [
        new TrustFramework("icp-brasil", new Lazy<ICountryExtension>(() => new IcpBrasilExtension())),
        new TrustFramework("govbr", new Lazy<ICountryExtension>(() => new GovBrExtension())),
    ]);

    public IReadOnlyList<TrustFramework> All { get; } = frameworks;

    /// <summary>
    /// The frameworks a request names: <paramref name="trust"/> (an id) or <paramref name="country"/> (a region code,
    /// every framework of that country); null when the request names neither.
    /// </summary>
    /// <exception cref="ArgumentException">The id or country is not one the agent knows.</exception>
    public IReadOnlyList<TrustFramework>? Select(string? country, string? trust)
    {
        if (!string.IsNullOrEmpty(trust))
        {
            return [All.FirstOrDefault(f => string.Equals(f.Id, trust, StringComparison.OrdinalIgnoreCase))
                ?? throw new ArgumentException(trust)];
        }

        if (!string.IsNullOrEmpty(country))
        {
            var matching = All.Where(f => string.Equals(f.Extension.Value.RegionCode, country, StringComparison.OrdinalIgnoreCase)).ToList();
            return matching.Count > 0 ? matching : throw new ArgumentException(country);
        }

        return null;
    }

    /// <summary>Whether <paramref name="certificate"/> chains to the anchors of one of <paramref name="selected"/>.</summary>
    public async Task<bool> AnyTrustsAsync(IReadOnlyList<TrustFramework> selected, X509Certificate2 certificate, CancellationToken cancellationToken)
    {
        foreach (var framework in selected)
        {
            if (await TrustsAsync(framework, certificate, cancellationToken))
            {
                return true;
            }
        }

        return false;
    }

    private async Task<bool> TrustsAsync(TrustFramework framework, X509Certificate2 certificate, CancellationToken cancellationToken)
    {
        var key = (framework.Id, certificate.Thumbprint);
        if (_trusted.TryGetValue(key, out bool known))
        {
            return known;
        }

        var providers = framework.Extension.Value.TrustAnchorProviders;
        var check = await SigningCertificateCheck.EvaluateAsync(certificate, new SigningCertificateCheckOptions
        {
            Chain = [.. providers.SelectMany(p => p.GetIntermediateCertificates())],
            Policy = s_chainPolicy,
            TrustAnchors = providers,
        }, cancellationToken);
        bool trusted = !check.Findings.Any(f => f.Constraint == TrustConstraint);
        _trusted[key] = trusted;
        return trusted;
    }

    /// <summary>
    /// Whether <paramref name="certificate"/> can sign now: valid today, with digitalSignature or nonRepudiation (the
    /// key usage <see cref="SigningPolicy.Default"/> asks for).
    /// </summary>
    public static bool CanSignNow(X509Certificate2 certificate)
    {
        var now = DateTime.UtcNow;
        if (certificate.NotBefore.ToUniversalTime() > now || certificate.NotAfter.ToUniversalTime() < now)
        {
            return false;
        }

        return certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault() is { } usage
            && (usage.KeyUsages & (X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation)) != 0;
    }
}
