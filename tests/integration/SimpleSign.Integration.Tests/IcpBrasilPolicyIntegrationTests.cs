using System.Net;
using Shouldly;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.PAdES.Inspection;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Integration.Tests;

/// <summary>ICP-Brasil policies and chains against real documents and the live ITI repository.</summary>
[Trait("Category", "Integration")]
public sealed class IcpBrasilPolicyIntegrationTests
{
    private static string FixturePath(string name) => Path.Combine("Fixtures", name);

    private static async Task<IReadOnlyList<CmsSignedData>> SignaturesOf(string fixture)
    {
        await using var stream = File.OpenRead(FixturePath(fixture));
        var inspection = await PdfSignatureInspector.InspectAsync(stream);
        return [.. inspection.Signatures.Select(s => CmsParser.Parse(s.CmsRawData.ToArray()))];
    }

    // A production PAdES AD-RB v1.0 signature carries the PA's signPolicyHash (501D69B4…),
    // not the digest of the PA file listed in the LPA (739A8249…): the catalog holds the former.
    [SkippableFact]
    public async Task AdRbFixture_PolicyHash_MatchesCatalog()
    {
        Skip.IfNot(File.Exists(FixturePath("AD-RB.pdf")), "AD-RB fixture not available");
        var cms = (await SignaturesOf("AD-RB.pdf"))[0];

        var check = IcpBrasilPolicyValidator.Validate(cms, cms.SigningTime ?? DateTimeOffset.UtcNow, IcpBrasilPolicyFormat.Pades);

        check.Reference!.Oid.ShouldBe("2.16.76.1.7.1.11.1");
        Convert.ToHexString(check.Reference.Hash.Span).ShouldStartWith("501D69B4");
        check.Errors.ShouldNotContain(e => e.Contains("sigPolicyHash", StringComparison.Ordinal));
    }

    // With only the signer certificate and no network, the chain builds from the bundled intermediates.
    [SkippableFact]
    public async Task IcpBrasilFixture_ChainBuildsOfflineFromBundledIntermediates()
    {
        Skip.IfNot(File.Exists(FixturePath("signed-icp-brasil.pdf")), "ICP-Brasil fixture not available");
        var cms = (await SignaturesOf("signed-icp-brasil.pdf"))[0];
        var offline = new HttpClient(new MockHttpHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable))));

        var result = await new IcpBrasilChainValidator(offline).ValidateAsync(new ChainValidationContext
        {
            Certificate = cms.SignerCertificate!,
            Certificates = [],
            ValidationTime = cms.SigningTime,
            CheckRevocation = false,
        });

        result.IsChainValid.ShouldBeTrue(string.Join("; ", result.Errors));
        result.ChainElements.Count.ShouldBeGreaterThanOrEqualTo(3);
    }

    [SkippableFact]
    public async Task RefreshAsync_LiveItiRepository_VerifiesAndApplies()
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
        IcpBrasilLpa lpa;
        try
        {
            lpa = await IcpBrasilSignaturePolicies.RefreshAsync(http, IcpBrasilPolicyFormat.Pades);
        }
        catch (HttpRequestException ex)
        {
            Skip.If(true, $"ITI repository unreachable: {ex.Message}");
            return;
        }

        lpa.Entries.Count.ShouldBeGreaterThanOrEqualTo(18);
        IcpBrasilSignaturePolicies.Current(IcpBrasilPolicy.AdRb, IcpBrasilPolicyFormat.Pades).Oid.ShouldStartWith("2.16.76.1.7.1.11.1.");
    }

    [SkippableFact]
    public async Task RefreshXadesAsync_LiveItiRepository_VerifiesAndApplies()
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
        IcpBrasilLpa lpa;
        try
        {
            lpa = await SimpleSign.Brazil.IcpBrasil.Xades.IcpBrasilXadesPolicies.RefreshAsync(http);
        }
        catch (HttpRequestException ex)
        {
            Skip.If(true, $"ITI repository unreachable: {ex.Message}");
            return;
        }

        lpa.Entries.Count.ShouldBeGreaterThanOrEqualTo(45);
        IcpBrasilSignaturePolicies.Current(IcpBrasilPolicy.AdRb, IcpBrasilPolicyFormat.Xades).Oid.ShouldStartWith("2.16.76.1.7.1.6.2.");
    }
}
