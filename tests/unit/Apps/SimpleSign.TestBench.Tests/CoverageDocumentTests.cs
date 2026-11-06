using Shouldly;
using SimpleSign.TestBench.Schema;
using SimpleSign.TestHelpers;

namespace SimpleSign.TestBench.Tests;

/// <summary>docs/articles/coverage.md is generated from the option schema and must not fall behind it.</summary>
[Trait("Category", "Unit")]
public sealed class CoverageDocumentTests
{
    private static readonly string s_path = RepositoryPaths.Get("docs", "articles", "coverage.md");

    [Fact]
    public void Generate_MatchesThePageInTheRepository()
    {
        string generated = CoverageDocument.Generate();
        if (Environment.GetEnvironmentVariable("SIMPLESIGN_UPDATE_DOCS") == "1")
        {
            File.WriteAllText(s_path, generated);
        }

        File.Exists(s_path).ShouldBeTrue("Run the tests once with SIMPLESIGN_UPDATE_DOCS=1 to write docs/articles/coverage.md.");
        File.ReadAllText(s_path).ReplaceLineEndings("\n").ShouldBe(generated,
            "The option schema changed: run the TestBench tests with SIMPLESIGN_UPDATE_DOCS=1 and commit docs/articles/coverage.md.");
    }

    [Fact]
    public void Generate_ListsEveryFormatAndWhatIsNotImplemented()
    {
        string page = CoverageDocument.Generate();

        page.ShouldContain("## PAdES");
        page.ShouldContain("## CAdES");
        page.ShouldContain("## XAdES");
        page.ShouldContain("## By standard");
        page.ShouldContain("### ETSI EN 319 142-1");
        page.ShouldContain("| **no** |");
        page.ShouldContain("(**BR**)");
    }
}
