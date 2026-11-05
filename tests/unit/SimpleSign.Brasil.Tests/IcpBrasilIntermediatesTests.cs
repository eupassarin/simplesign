using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Brasil.IcpBrasil;
using SimpleSign.Core.Extensions;

namespace SimpleSign.Brasil.Tests;

/// <summary>The bundled ICP-Brasil intermediate ACs (scripts/update-icp-intermediates.sh).</summary>
[Trait("Category", "Unit")]
public sealed class IcpBrasilIntermediatesTests
{
    [Fact]
    public void Bundled_ContainsIntermediatesOnly()
    {
        var intermediates = IcpBrasilChainValidator.LoadBundledIntermediateCerts();

        intermediates.Count.ShouldBeGreaterThan(150);
        intermediates.ShouldAllBe(c => !c.IsSelfSigned());
        intermediates.ShouldAllBe(c => c.Subject.Contains("ICP-Brasil", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Bundled_EveryIntermediateChainsToABundledRoot()
    {
        var roots = IcpBrasilRoots.Bundled;
        var intermediates = IcpBrasilChainValidator.LoadBundledIntermediateCerts();
        var all = roots.Concat(intermediates).ToList();
        var failures = new List<string>();
        foreach (var certificate in intermediates)
        {
            // AC SAFEWEB CD V12 encodes its issuer name as PrintableString while its issuer's
            // subject is UTF8String. RFC 5280 §7.1 treats them as equal (OpenSSL does); macOS
            // compares the bytes and reports a partial chain. The link is still checked, with
            // normalized names, by Bundled_EveryIntermediateHasItsIssuerBundled.
            if (OperatingSystem.IsMacOS() && !all.Any(i => i.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData)))
            {
                continue;
            }

            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            foreach (var root in roots)
            {
                chain.ChainPolicy.CustomTrustStore.Add(root);
            }

            foreach (var intermediate in intermediates)
            {
                chain.ChainPolicy.ExtraStore.Add(intermediate);
            }

            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            // Chaining, not validity in time, is what this checks.
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
            chain.ChainPolicy.VerificationTime = certificate.NotBefore.AddDays(1);
            if (!chain.Build(certificate))
            {
                failures.Add($"{certificate.Subject}: {string.Join(", ", chain.ChainStatus.Select(s => s.Status))}");
            }
        }

        failures.ShouldBeEmpty();
    }

    [Fact]
    public void Bundled_EveryIntermediateHasItsIssuerBundled()
    {
        var all = IcpBrasilRoots.Bundled.Concat(IcpBrasilChainValidator.LoadBundledIntermediateCerts()).ToList();
        var missing = IcpBrasilChainValidator.LoadBundledIntermediateCerts()
            .Where(c => !all.Any(issuer => SameName(issuer.SubjectName, c.IssuerName)
                && KeyId(issuer) is { } ski && AuthorityKeyId(c) is { } aki && ski == aki))
            .Select(c => c.Subject)
            .ToList();

        missing.ShouldBeEmpty();
    }

    /// <summary>Name comparison after decoding (string type and case ignored, RFC 5280 §7.1).</summary>
    private static bool SameName(X500DistinguishedName a, X500DistinguishedName b) =>
        string.Equals(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);

    private static string? KeyId(X509Certificate2 certificate) =>
        certificate.Extensions.OfType<X509SubjectKeyIdentifierExtension>().SingleOrDefault()?.SubjectKeyIdentifier;

    private static string? AuthorityKeyId(X509Certificate2 certificate) =>
        certificate.Extensions.OfType<X509AuthorityKeyIdentifierExtension>().SingleOrDefault()?.KeyIdentifier is { } id
            ? Convert.ToHexString(id.Span)
            : null;

    [Fact]
    public void TrustAnchorProvider_ExposesIntermediates()
    {
        ITrustAnchorProvider provider = new IcpBrasilTrustAnchorProvider();

        provider.GetIntermediateCertificates().Count.ShouldBe(IcpBrasilChainValidator.LoadBundledIntermediateCerts().Count);
        provider.GetTrustAnchors().ShouldAllBe(c => c.IsSelfSigned());
    }
}
