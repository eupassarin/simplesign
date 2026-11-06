using System.Net;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Brasil.IcpBrasil;
using SimpleSign.Core.Extensions;
using SimpleSign.TestHelpers;

namespace SimpleSign.Brasil.Tests;

/// <summary>The bundled ICP-Brasil homologation hierarchy (scripts/update-icp-homologation.sh).</summary>
[Trait("Category", "Unit")]
public sealed class IcpBrasilHomologationTests
{
    private const string ProductionV12Name = "CN=Autoridade Certificadora Raiz Brasileira v12, OU=Instituto Nacional de Tecnologia da Informacao - ITI, O=ICP-Brasil, C=BR";

    [Fact]
    public void Bundled_HasTestRootsAndIntermediates()
    {
        var roots = IcpBrasilChainValidator.LoadBundledHomologationRoots();
        var intermediates = IcpBrasilChainValidator.LoadBundledHomologationIntermediates();

        roots.Count.ShouldBeGreaterThanOrEqualTo(4);
        roots.ShouldAllBe(c => c.IsSelfSigned());
        intermediates.ShouldAllBe(c => !c.IsSelfSigned());
        roots.ShouldContain(c => c.Subject.Contains("Raiz Brasileira v12 - HOM", StringComparison.Ordinal));
    }

    [Fact]
    public void Bundled_NoHomologationCertificateIsAProductionRoot()
    {
        var production = IcpBrasilChainValidator.LoadBundledAcRaizCerts();
        var homologation = IcpBrasilChainValidator.LoadBundledHomologationRoots()
            .Concat(IcpBrasilChainValidator.LoadBundledHomologationIntermediates());

        var productionThumbprints = production.Select(p => p.Thumbprint).ToHashSet();
        homologation.ShouldAllBe(h => !productionThumbprints.Contains(h.Thumbprint));
        production.ShouldAllBe(p => !IcpBrasilChainValidator.IsHomologationRoot(p));
    }

    [Fact]
    public void Bundled_EveryIntermediate_ChainsToABundledHomologationRoot()
    {
        var roots = IcpBrasilChainValidator.LoadBundledHomologationRoots();
        var intermediates = IcpBrasilChainValidator.LoadBundledHomologationIntermediates();
        var failures = new List<string>();
        foreach (var certificate in intermediates)
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.AddRange(roots.ToArray());
            chain.ChainPolicy.ExtraStore.AddRange(intermediates.ToArray());
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            // Chaining, not validity in time, is what this checks.
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
            chain.ChainPolicy.VerificationTime = certificate.NotBefore.AddDays(1);
            if (!chain.Build(certificate) || !IcpBrasilChainValidator.IsHomologationRoot(chain.ChainElements[^1].Certificate))
            {
                failures.Add($"{certificate.Subject}: {string.Join(", ", chain.ChainStatus.Select(s => s.Status))}");
            }
        }

        failures.ShouldBeEmpty();
    }

    [Fact]
    public void IsHomologationRoot_TestRootWithProductionV12Name_IsHomologationNotProduction()
    {
        // A test root reuses the exact name of the production AC Raiz v12 with another key.
        var impostor = IcpBrasilChainValidator.LoadBundledHomologationRoots().Single(c => c.Subject == ProductionV12Name);
        var productionV12 = IcpBrasilChainValidator.LoadBundledAcRaizCerts().Single(c => c.Subject == ProductionV12Name);

        IcpBrasilChainValidator.IsHomologationRoot(impostor).ShouldBeTrue();
        impostor.PublicKey.EncodedKeyValue.RawData.ShouldNotBe(productionV12.PublicKey.EncodedKeyValue.RawData);
    }

    [Theory]
    [InlineData("Autoridade Certificadora SERPRO v5 - Hom")]
    [InlineData("Autoridade Certificadora SERPRO v5 - HOM")]
    public async Task ValidateAsync_TestCa_RejectedInProduction(string commonName)
    {
        var testCa = TestCa(commonName);

        var result = await Validator(IcpBrasilEnvironment.Production).ValidateAsync(Context(testCa));

        result.IsChainValid.ShouldBeFalse(Describe(result));
        result.IsHomologation.ShouldBeFalse();
    }

    [Theory]
    [InlineData("Autoridade Certificadora SERPRO v5 - Hom")]
    [InlineData("Autoridade Certificadora SERPRO v5 - HOM")]
    public async Task ValidateAsync_TestCa_AcceptedAsHomologation(string commonName)
    {
        var testCa = TestCa(commonName);

        var result = await Validator(IcpBrasilEnvironment.Homologation).ValidateAsync(Context(testCa));

        result.IsChainValid.ShouldBeTrue(string.Join("; ", result.Errors));
        result.IsHomologation.ShouldBeTrue();
        result.Warnings.ShouldContain(w => w.Contains("homologation", StringComparison.Ordinal));
    }

    [Fact]
    public void FindBundledRoot_TestCa_OnlyInHomologation()
    {
        var testCa = TestCa("Autoridade Certificadora SERPRO v5 - HOM");

        IcpBrasilChainValidator.FindBundledRoot(testCa).ShouldBeNull(testCa.Issuer);
        var root = IcpBrasilChainValidator.FindBundledRoot(testCa, null, IcpBrasilEnvironment.Homologation).ShouldNotBeNull();
        IcpBrasilChainValidator.IsHomologationRoot(root).ShouldBeTrue();
    }

    [Fact]
    public async Task Provider_TestCa_ReportsEnvironmentAndNoLei14063Level()
    {
        var provider = new IcpBrasilChainValidationProvider(Validator(IcpBrasilEnvironment.Homologation));

        var result = await provider.ValidateAsync(Context(TestCa("Autoridade Certificadora SERPRO v5 - Hom")), CancellationToken.None);

        var metadata = result.Metadata.ShouldNotBeNull();
        metadata["BR.Environment"].ShouldBe("Homologation");
        metadata.ContainsKey(Lei14063.MetadataKey).ShouldBeFalse();
        result.Errors.ShouldNotBeNull().ShouldContain(e => e.Contains("homologation", StringComparison.Ordinal));
    }

    [Fact]
    public void TrustAnchorProvider_Homologation_IncludesTestRoots()
    {
        ITrustAnchorProvider production = new IcpBrasilTrustAnchorProvider([]);
        ITrustAnchorProvider homologation = new IcpBrasilTrustAnchorProvider([], IcpBrasilEnvironment.Homologation);

        production.GetTrustAnchors().ShouldAllBe(c => !IcpBrasilChainValidator.IsHomologationRoot(c));
        homologation.GetTrustAnchors().Count(IcpBrasilChainValidator.IsHomologationRoot)
            .ShouldBe(IcpBrasilChainValidator.LoadBundledHomologationRoots().Count);
    }

    private static string Describe(IcpBrasilValidationResult result) =>
        string.Join(" <- ", result.ChainElements.Select(e => $"{e.Subject} [{e.Thumbprint}] {string.Join(",", e.Errors)}"))
        + " | errors: " + string.Join("; ", result.Errors);

    private static X509Certificate2 TestCa(string commonName) =>
        IcpBrasilChainValidator.LoadBundledHomologationIntermediates().Single(c => c.GetNameInfo(X509NameType.SimpleName, false) == commonName);

    private static ChainValidationContext Context(X509Certificate2 certificate) => new()
    {
        Certificate = certificate,
        ValidationTime = certificate.NotBefore.AddDays(1),
        CheckRevocation = false,
    };

    private static IcpBrasilChainValidator Validator(IcpBrasilEnvironment environment) =>
        new(new HttpClient(new MockHttpHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)))))
        {
            Environment = environment,
        };
}
