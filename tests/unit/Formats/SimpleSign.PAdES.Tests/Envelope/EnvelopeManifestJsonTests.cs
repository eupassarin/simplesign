using System.Text;
using Shouldly;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES.Envelope;
using Xunit;

namespace SimpleSign.PAdES.Tests.Envelope;

[Trait("Category", "Unit")]
public sealed class EnvelopeManifestJsonTests
{
    private static readonly EnvelopeManifest s_manifest = new()
    {
        Id = "e-1",
        Order = EnvelopeOrder.Parallel,
        PreparedAt = new DateTimeOffset(2026, 11, 23, 9, 0, 0, TimeSpan.FromHours(-3)),
        Signers =
        [
            new EnvelopeManifestSigner
            {
                Field = "SimpleSign_1",
                Name = "Maria",
                Role = "Diretora",
                Email = "maria@example.com",
                External = true,
                Identifiers = [new EnvelopeIdentifier("CPF", "12345678909") { AlsoAccept = ["RESPONSIBLE-CPF"] }],
                Level = new EnvelopeLevel
                {
                    Id = "icp-ad-rt", Baseline = AdesBaselineLevel.Timestamped, Timestamp = true,
                    SubFilters = ["PBAD.PAdES"], PolicyOids = ["2.16.76.1.7.1.12.1.3"],
                },
            },
        ],
    };

    [Fact]
    public void Serialize_WritesVersionOneInCamelCase()
    {
        string json = Encoding.UTF8.GetString(EnvelopeManifestJson.Serialize(s_manifest));

        json.ShouldContain("\"version\": 1");
        json.ShouldContain("\"order\": \"parallel\"");
        json.ShouldContain("\"preparedAt\": \"2026-11-23T12:00:00Z\"");
        json.ShouldContain("\"alsoAccept\": [");
        json.ShouldContain("\"baseline\": \"B-T\"");
        json.ShouldContain("\"policyOids\": [");
    }

    [Fact]
    public void Parse_WhatSerializeWrites_GivesTheSameManifest()
    {
        var parsed = EnvelopeManifestJson.Parse(EnvelopeManifestJson.Serialize(s_manifest));

        parsed.Id.ShouldBe("e-1");
        parsed.Order.ShouldBe(EnvelopeOrder.Parallel);
        parsed.PreparedAt.ShouldBe(s_manifest.PreparedAt);
        var signer = parsed.Signers.ShouldHaveSingleItem();
        signer.External.ShouldBeTrue();
        signer.Identifiers.Single().AlsoAccept.ShouldBe(["RESPONSIBLE-CPF"]);
        signer.Level.Baseline.ShouldBe(AdesBaselineLevel.Timestamped);
        signer.Level.SubFilters.ShouldBe(["PBAD.PAdES"]);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("{\"version\": 2, \"id\": \"x\", \"order\": \"sequential\", \"preparedAt\": \"2026-01-01T00:00:00Z\", \"signers\": []}")]
    [InlineData("{\"version\": 1, \"id\": \"x\", \"order\": \"sequential\", \"preparedAt\": \"2026-01-01T00:00:00Z\", \"signers\": []}")]
    [InlineData("{\"version\": 1, \"id\": \"x\", \"order\": \"random\", \"preparedAt\": \"2026-01-01T00:00:00Z\", \"signers\": [{\"field\": \"a\", \"name\": \"b\", \"level\": {\"id\": \"any\"}}]}")]
    [InlineData("{\"version\": 1, \"id\": \"x\", \"order\": \"sequential\", \"preparedAt\": \"2026-01-01T00:00:00Z\", \"signers\": [{\"field\": \"a\", \"name\": \"b\", \"level\": {\"id\": \"any\", \"baseline\": \"B-X\"}}]}")]
    public void Parse_NotAVersionOneManifest_Throws(string json) =>
        Should.Throw<FormatException>(() => EnvelopeManifestJson.Parse(Encoding.UTF8.GetBytes(json)));
}
