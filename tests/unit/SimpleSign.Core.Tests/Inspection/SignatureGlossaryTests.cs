using Shouldly;
using SimpleSign.Core.Inspection;
using Xunit;

namespace SimpleSign.Core.Tests.Inspection;

public sealed class SignatureGlossaryTests
{
    [Fact(DisplayName = "All returns non-empty collection")]
    public void All_ReturnsEntries()
    {
        SignatureGlossary.All.ShouldNotBeEmpty();
        SignatureGlossary.All.Count().ShouldBeGreaterThan(30);
    }

    [Fact(DisplayName = "AllCategories returns distinct non-empty list")]
    public void AllCategories_ReturnsDistinctCategories()
    {
        var categories = SignatureGlossary.AllCategories;
        categories.ShouldNotBeEmpty();
        categories.Distinct().Count().ShouldBe(categories.Count());
        categories.ShouldContain(SignatureGlossary.Categories.SignatureDictionary);
        categories.ShouldContain(SignatureGlossary.Categories.DssLtv);
    }

    [Theory(DisplayName = "Lookup finds known entries by key (case-insensitive)")]
    [InlineData("/DSS", "/DSS")]
    [InlineData("/dss", "/DSS")]
    [InlineData("/ByteRange", "/ByteRange")]
    [InlineData("SHA-256", "SHA-256")]
    [InlineData("PAdES B-LTA", "PAdES B-LTA")]
    public void Lookup_KnownKey_ReturnsEntry(string key, string expectedKey)
    {
        var entry = SignatureGlossary.Lookup(key);
        entry.ShouldNotBeNull();
        entry!.Key.ShouldBe(expectedKey);
        entry.DisplayName.ShouldNotBeNullOrWhiteSpace();
        entry.ShortDescription.ShouldNotBeNullOrWhiteSpace();
    }

    [Fact(DisplayName = "Lookup returns null for unknown key")]
    public void Lookup_UnknownKey_ReturnsNull()
    {
        SignatureGlossary.Lookup("NonExistentTerm123").ShouldBeNull();
    }

    [Fact(DisplayName = "Search finds entries matching query in key, name, or description")]
    public void Search_MatchesAcrossFields()
    {
        var results = SignatureGlossary.Search("timestamp");
        results.ShouldNotBeEmpty("'timestamp' should match several entries");
        results.ShouldContain(e => e.Key == "TSA");
    }

    [Theory(DisplayName = "Search returns empty for blank or null query")]
    [InlineData("")]
    [InlineData("   ")]
    public void Search_BlankQuery_ReturnsEmpty(string query)
    {
        SignatureGlossary.Search(query).ShouldBeEmpty();
    }

    [Fact(DisplayName = "ByCategory returns entries for known category")]
    public void ByCategory_ReturnsFilteredEntries()
    {
        var entries = SignatureGlossary.ByCategory(SignatureGlossary.Categories.Algorithm);
        entries.ShouldNotBeEmpty();
        entries.ShouldAllBe(e => e.Category == SignatureGlossary.Categories.Algorithm);
    }

    [Fact(DisplayName = "ByCategory returns empty for unknown category")]
    public void ByCategory_UnknownCategory_ReturnsEmpty()
    {
        SignatureGlossary.ByCategory("FakeCategory").ShouldBeEmpty();
    }

    [Fact(DisplayName = "GetInlineComment returns description for known key")]
    public void GetInlineComment_KnownKey_ReturnsDescription()
    {
        var comment = SignatureGlossary.GetInlineComment("/DSS");
        comment.ShouldNotBeNullOrWhiteSpace();
    }

    [Fact(DisplayName = "GetInlineComment returns null for unknown key")]
    public void GetInlineComment_UnknownKey_ReturnsNull()
    {
        SignatureGlossary.GetInlineComment("Unknown").ShouldBeNull();
    }

    [Fact(DisplayName = "Every entry has non-empty key, display name, category, and description")]
    public void AllEntries_HaveRequiredFields()
    {
        foreach (var entry in SignatureGlossary.All)
        {
            entry.Key.ShouldNotBeNullOrWhiteSpace($"entry should have a key");
            entry.DisplayName.ShouldNotBeNullOrWhiteSpace($"'{entry.Key}' should have a display name");
            entry.Category.ShouldNotBeNullOrWhiteSpace($"'{entry.Key}' should have a category");
            entry.ShortDescription.ShouldNotBeNullOrWhiteSpace($"'{entry.Key}' should have a description");
        }
    }
}
