using Shouldly;
using SimpleSign.Cli.Commands;
using SimpleSign.Core.Signing;

namespace SimpleSign.Cli.Tests;

[Trait("Category", "Unit")]
public sealed class AdesOptionSupportTests
{
    [Theory]
    [InlineData("ocsp", RevocationPreference.OcspFirst)]
    [InlineData("OCSP-first", RevocationPreference.OcspFirst)]
    [InlineData("crl", RevocationPreference.CrlFirst)]
    [InlineData("crl-first", RevocationPreference.CrlFirst)]
    public void ParseRevocationPreference_KnownValue_IsParsed(string value, RevocationPreference expected) =>
        AdesOptionSupport.ParseRevocationPreference(value).ShouldBe(expected);

    [Fact]
    public void LongTermOptions_NoPreference_IsOcspFirst() =>
        AdesOptionSupport.LongTermOptions(null).RevocationPreference.ShouldBe(RevocationPreference.OcspFirst);

    [Fact]
    public void LongTermOptions_Crl_IsCrlFirst() =>
        AdesOptionSupport.LongTermOptions("crl").RevocationPreference.ShouldBe(RevocationPreference.CrlFirst);

    [Theory]
    [InlineData("file.pdf,application/pdf", "file.pdf", "application/pdf")]
    [InlineData("file.pdf", "file.pdf", null)]
    [InlineData("file.pdf,", "file.pdf", null)]
    [InlineData("a,b.pdf,text/plain", "a,b.pdf", "text/plain")]
    public void SplitPathAndMimeType_SplitsAtTheLastComma(string value, string path, string? mimeType) =>
        AdesOptionSupport.SplitPathAndMimeType(value).ShouldBe((path, mimeType));

    [Fact]
    public void SplitPathAndMimeType_ExistingFileWithAComma_IsThePath()
    {
        string path = Path.Combine(Path.GetTempPath(), $"simplesign,{Guid.NewGuid():N}.bin");
        File.WriteAllBytes(path, [1]);
        try
        {
            AdesOptionSupport.SplitPathAndMimeType(path).ShouldBe((path, null));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData("terms.txt=/tmp/terms.txt,text/plain", "terms.txt", "/tmp/terms.txt", "text/plain")]
    [InlineData("https://example.com/a?x=1", "https://example.com/a?x", "1", null)]
    public void SplitUriAndPath_SplitsAtTheFirstEquals(string value, string uri, string path, string? mimeType) =>
        AdesOptionSupport.SplitUriAndPath(value).ShouldBe((uri, path, mimeType));

    [Theory]
    [InlineData("terms.txt")]
    [InlineData("=path")]
    [InlineData("uri=")]
    public void SplitUriAndPath_WithoutBothSides_IsNull(string value) =>
        AdesOptionSupport.SplitUriAndPath(value).ShouldBeNull();
}
