using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Peru.Iofe;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Integration.Tests;

/// <summary>
/// INDECOPI's live trusted list (<see cref="IofeExtensionOptions.DefaultTrustedListUrl"/>), read with
/// <see cref="IofeExtension"/>. The list's signature is checked against the TSL Suscriptor certificate kept in the IOFE
/// unit tests' Fixtures (tsl-pe-signer.pem, its fingerprint to be confirmed with INDECOPI: see Fixtures/README.md), never
/// against a certificate taken from the download. Skipped when INDECOPI cannot be reached.
/// </summary>
[Trait("Category", "Integration")]
public sealed class IofeTrustedListIntegrationTests(ITestOutputHelper output)
{
    private static readonly string[] TsaCommonNames =
    [
        "Camerfirma TSA II - 2014",
        "Acepta Peru Autoridad de Sellado de Tiempo - V1",
        "Llama.pe Timestamping CA",
        "BPO TSA",
        "FirmEasy TSA",
    ];

    [SkippableFact]
    public async Task LoadAsync_LiveList_VerifiesAndHasTheTimestampingServicesButNoSignatureSoftware()
    {
        var signer = X509Certificate2.CreateFromPem(await File.ReadAllTextAsync(Path.Combine("Fixtures", "iofe", "tsl-pe-signer.pem")));
        IofeExtension iofe;
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            iofe = await IofeExtension.LoadAsync(new IofeExtensionOptions { TrustedListSigners = [signer] }, timeout.Token);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or OperationCanceledException)
        {
            Skip.If(true, $"INDECOPI's trusted list could not be downloaded: {ex.Message}");
            return;
        }

        var list = iofe.TrustedList;
        output.WriteLine($"Sequence {list.SequenceNumber}, issued {list.IssueDate:u}, next update {list.NextUpdate:u}, {list.Services.Count} services");
        list.Territory.ShouldBe("PE");
        var anchors = list.GetTrustAnchors();
        var names = anchors.Select(c => c.GetNameInfo(X509NameType.SimpleName, false)).ToList();
        foreach (string tsa in TsaCommonNames)
        {
            names.ShouldContain(tsa, $"The live list (sequence {list.SequenceNumber}) no longer has {tsa}: check it and update the fixtures.");
        }

        anchors.Where(c => c.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault() is not { CertificateAuthority: true }
                && c.Extensions.OfType<X509EnhancedKeyUsageExtension>().Any(e => e.EnhancedKeyUsages.Cast<System.Security.Cryptography.Oid>().Any(o => o.Value == "1.3.6.1.5.5.7.3.3")))
            .ShouldBeEmpty("a code-signing certificate (signature software) became a trust anchor");
    }
}
