using System.Text.Json;
using Shouldly;
using SimpleSign.Core.Signing;
using SimpleSign.TestBench.Cades;
using SimpleSign.TestBench.CrossValidation;
using SimpleSign.TestBench.Signing;
using SimpleSign.TestBench.Xml;
using SimpleSign.XAdES;
using Xunit.Abstractions;

namespace SimpleSign.TestBench.Tests;

/// <summary>
/// Sends signatures that use the optional ETSI attributes and properties to the EU DSS and checks
/// what it reads from them: every signature and timestamp intact, every signed reference found,
/// the structure valid, the baseline level the one asked for. The checks do not depend on which
/// roots DSS trusts. Skipped when no DSS answers at <c>SIMPLESIGN_DSS_URL</c> (default
/// <c>http://localhost:8080</c>): start one with <c>tools/dss/docker-compose.yml</c>.
/// </summary>
[Collection(TestBenchCollection.Name)]
[Trait("Category", "Integration")]
public sealed class DssCrossValidationTests(TestBenchFixture fixture, ITestOutputHelper output)
{
    [SkippableTheory]
    [InlineData("signed-attributes", "B")]
    [InlineData("content-timestamp", "T")]
    [InlineData("crl-first", "LT")]
    [InlineData("policy-store", "LTA")]
    public async Task Cades_OptionalAttributes_DssReadsAnIntactSignature(string scenario, string level)
    {
        using var dss = await ConnectAsync();
        var options = new CadesOptions
        {
            DataId = fixture.CadesSamples.Single(s => s.Id == "text").FileId,
            CredentialId = fixture.Sandboxed(),
            Level = Level(level),
        };
        options = scenario switch
        {
            "signed-attributes" => options with
            {
                SignerCountry = "BR",
                SignerLocality = "Recife",
                SignerPostalAddress = ["Rua da Aurora, 1", "50050-000"],
                SignerRoles = ["Diretor"],
                MimeType = "text/plain",
                ContentDescription = "Contrato",
            },
            "content-timestamp" => options with { ContentTimestamp = true },
            "crl-first" => options with { RevocationPreference = RevocationPreference.CrlFirst },
            _ => options with
            {
                Kind = CadesKind.CustomPolicy,
                PolicyDocumentId = fixture.Documents.Add("policy.der", "a signature policy document"u8.ToArray()).Id,
                PolicySpecification = "1.2.3.4.5.1",
            },
        };

        var result = await fixture.Cades.RunAsync(options, default);

        result.Error.ShouldBeNull(string.Join("; ", result.Issues.Select(i => i.Message)));
        using var report = await ValidateAsync(dss, result.OutputId!, options.DataId, null);
        AssertIntact(report.RootElement, signatures: 1, "CAdES-BASELINE-" + level);
    }

    [SkippableTheory]
    [InlineData("default", "B")]
    [InlineData("place+inclusive", "T")]
    [InlineData("data-timestamp+objects", "LTA")]
    [InlineData("policy-store", "LTA")]
    [InlineData("crl-first", "LT")]
    public async Task Xades_OptionalProperties_DssReadsAnIntactSignature(string scenario, string level)
    {
        using var dss = await ConnectAsync();
        var options = Xades() with { Level = Level(level) };
        var terms = scenario == "data-timestamp+objects" ? fixture.Documents.Add("termos.txt", "Termos e condições"u8.ToArray()) : null;
        options = scenario switch
        {
            "place+inclusive" => options with
            {
                PlaceCity = "Recife",
                PlaceStreet = "Rua da Aurora, 1",
                PlaceState = "PE",
                PlaceCountry = "BR",
                Canonicalization = XadesCanonicalization.Inclusive,
            },
            "data-timestamp+objects" => options with
            {
                DataObjectsTimestamp = true,
                EmbeddedObjectId = fixture.Documents.Add("anexo.bin", [0x25, 0x50, 0x44, 0x46, 0x00, 0xFF]).Id,
                ExternalObjectId = terms!.Id,
            },
            "policy-store" => options with
            {
                Kind = XadesKind.CustomPolicy,
                PolicyDocumentId = fixture.Documents.Add("policy.xml", "<policy>a signature policy document</policy>"u8.ToArray()).Id,
                PolicySpecification = "https://example.com/policy-syntax",
            },
            "crl-first" => options with { RevocationPreference = RevocationPreference.CrlFirst },
            _ => options,
        };

        var result = await fixture.Xml.RunAsync(options, default);

        result.Success.ShouldBeTrue(result.Error);
        using var report = await ValidateAsync(dss, result.OutputId!, terms?.Id, terms?.FileName);
        AssertIntact(report.RootElement, signatures: 1, "XAdES-BASELINE-" + level);
    }

    [SkippableFact]
    public async Task Xades_CounterSignature_DssReadsBothSignatures()
    {
        using var dss = await ConnectAsync();
        var signed = await fixture.Xml.RunAsync(Xades(), default);
        signed.Success.ShouldBeTrue(signed.Error);

        var result = await fixture.Xml.RunAsync(
            Xades("rsa-3072") with { DataId = signed.OutputId!, CounterSign = true, Level = BaselineLevel.BT }, default);

        result.Success.ShouldBeTrue(result.Error);
        using var report = await ValidateAsync(dss, result.OutputId!, null, null);
        AssertIntact(report.RootElement, signatures: 2, format: null);
        var all = report.RootElement.GetProperty("DiagnosticData").GetProperty("Signature").EnumerateArray().ToList();
        all.Count(s => s.TryGetProperty("CounterSignature", out var counter) && counter.ValueKind == JsonValueKind.True).ShouldBe(1);
    }

    [SkippableFact]
    public async Task Xades_ProductionPlaceWithThe132Form_DssReadsAnIntactSignature()
    {
        using var dss = await ConnectAsync();
        var options = Xades() with { SigningCertificateV1 = true, PlaceCity = "Recife", PlaceCountry = "BR" };

        var result = await fixture.Xml.RunAsync(options, default);

        result.Success.ShouldBeTrue(result.Error);
        using var report = await ValidateAsync(dss, result.OutputId!, null, null);
        AssertIntact(report.RootElement, signatures: 1, format: null);
    }

    private XmlOptions Xades(string signer = "rsa-2048") => new()
    {
        DataId = fixture.XmlSamples.Single(s => s.Id == "order").FileId,
        CredentialId = fixture.Sandboxed(signer),
    };

    private static BaselineLevel Level(string level) => level switch
    {
        "B" => BaselineLevel.BB,
        "T" => BaselineLevel.BT,
        "LT" => BaselineLevel.BLT,
        _ => BaselineLevel.BLTA,
    };

    /// <summary>A client for the DSS service; skips the test when the service is not there.</summary>
    private async Task<DssClient> ConnectAsync()
    {
        var dss = new DssClient(fixture.Documents);
        bool isDss = false;
        try
        {
            // The DSS demo web application lists its services with Apache CXF.
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(4) };
            string url = dss.Settings.Url.TrimEnd('/') + "/services/";
            isDss = (await http.GetStringAsync(new Uri(url))).Contains("CXF", StringComparison.Ordinal);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or UriFormatException)
        {
        }

        if (!isDss)
        {
            string where = dss.Settings.Url;
            dss.Dispose();
            Skip.If(true, $"No DSS at {where}: docker compose -f tools/dss/docker-compose.yml up");
        }

        return dss;
    }

    private async Task<JsonDocument> ValidateAsync(DssClient dss, string fileId, string? originalId, string? originalName)
    {
        var comparison = await dss.ValidateAsync(fileId, originalId, logger: null, default, originalName);
        comparison.Available.ShouldBeTrue(comparison.Error);
        return JsonDocument.Parse(fixture.Documents.Get(comparison.ReportId!).Content);
    }

    /// <summary>What DSS parsed must be whole: signatures and timestamps intact, references found, structure valid.</summary>
    private void AssertIntact(JsonElement report, int signatures, string? format)
    {
        var data = report.GetProperty("DiagnosticData");
        var found = data.GetProperty("Signature").EnumerateArray().ToList();
        found.Count.ShouldBe(signatures);
        foreach (var signature in found)
        {
            string id = signature.GetProperty("Id").GetString()!;
            string? detected = signature.TryGetProperty("SignatureFormat", out var f) ? f.GetString() : null;
            output.WriteLine($"{id[..Math.Min(12, id.Length)]} {detected}");
            var basic = signature.GetProperty("BasicSignature");
            basic.GetProperty("SignatureIntact").GetBoolean().ShouldBeTrue($"signature {id} is not intact");
            basic.GetProperty("SignatureValid").GetBoolean().ShouldBeTrue($"signature {id} is not valid");
            if (signature.TryGetProperty("StructuralValidation", out var structure) && structure.ValueKind == JsonValueKind.Object
                && structure.TryGetProperty("valid", out var valid))
            {
                valid.GetBoolean().ShouldBeTrue($"structure of {id}: {structure}");
            }

            AssertDigests(signature, id);
            if (format is not null)
            {
                detected.ShouldBe(format);
            }
        }

        if (data.TryGetProperty("Timestamp", out var timestamps) && timestamps.ValueKind == JsonValueKind.Array)
        {
            foreach (var timestamp in timestamps.EnumerateArray())
            {
                string type = timestamp.GetProperty("Type").GetString()!;
                timestamp.GetProperty("BasicSignature").GetProperty("SignatureIntact").GetBoolean().ShouldBeTrue($"timestamp {type} is not intact");
                AssertDigests(timestamp, type);
            }
        }
    }

    private static void AssertDigests(JsonElement token, string name)
    {
        if (!token.TryGetProperty("DigestMatcher", out var matchers) || matchers.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var matcher in matchers.EnumerateArray())
        {
            string what = $"{name}: {matcher}";
            matcher.GetProperty("DataFound").GetBoolean().ShouldBeTrue(what);
            matcher.GetProperty("DataIntact").GetBoolean().ShouldBeTrue(what);
        }
    }
}
