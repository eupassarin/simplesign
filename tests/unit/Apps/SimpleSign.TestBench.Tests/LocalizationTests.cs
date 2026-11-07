using System.Globalization;
using System.Text.RegularExpressions;
using Shouldly;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Localization;
using SimpleSign.TestBench.Signing;

namespace SimpleSign.TestBench.Tests;

/// <summary>Every text the backend shows has its pt-BR version, with the same placeholders.</summary>
[Collection(TestBenchCollection.Name)]
[Trait("Category", "Unit")]
public sealed partial class LocalizationTests(TestBenchFixture fixture)
{
    [SkippableFact]
    public void Translations_EveryLiteralPassedToT_IsTranslated()
    {
        string root = RepositoryRoot();
        var missing = new List<string>();
        foreach (string file in Directory.EnumerateFiles(Path.Combine(root, "src", "Apps", "SimpleSign.TestBench"), "*.cs", SearchOption.AllDirectories)
                     .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)))
        {
            foreach (Match match in TCall().Matches(File.ReadAllText(file)))
            {
                string text = Regex.Unescape(match.Groups[1].Value);
                if (!Translations.All.ContainsKey(text))
                {
                    missing.Add($"{Path.GetFileName(file)}: {text}");
                }
            }
        }

        missing.ShouldBeEmpty();
    }

    [SkippableFact]
    public void Translations_CatalogAndSamples_AreTranslated()
    {
        // The Sandbox's own texts (signers, CSC credentials) come from the Sandbox app, in English.
        var texts = OptionCatalog.All.Values.SelectMany(i => new[] { i.Title, i.Summary, i.Details })
            .Concat(fixture.Documents.Samples.SelectMany(s => new[] { s.Title, s.Description }))
            .Concat((fixture.SandboxProblem is null ? fixture.ValidationSamples : []).SelectMany(s => new[] { s.Title, s.Description }))
            .Concat((fixture.SandboxProblem is null ? fixture.CadesSamples : []).SelectMany(s => new[] { s.Title, s.Description }))
            .Concat((fixture.SandboxProblem is null ? fixture.XmlSamples : []).SelectMany(s => new[] { s.Title, s.Description }))
            .OfType<string>();

        texts.Where(t => !Translations.All.ContainsKey(t)).ShouldBeEmpty();
    }

    [SkippableFact]
    public async Task Translations_CredentialNotes_AreTranslated()
    {
        fixture.RequireSandbox();
        var handles = new List<CredentialHandle>
        {
            fixture.Factory.OpenSandbox(new SandboxCredentialRequest("expired")),
            await fixture.Factory.OpenCscAsync(new CscCredentialRequest(null, CscServiceAuth.Token, null, null, null, "rsa-scal1", CscAuthorizerKind.Explicit, fixture.Sandbox.Connection.Info.Csc.Pin, null), default),
        };

        // "{0}": a text of the Sandbox app, shown as it comes.
        handles.SelectMany(h => h.Notes).Select(n => n.English).Where(t => t != "{0}" && !Translations.All.ContainsKey(t)).ShouldBeEmpty();
    }

    [SkippableFact]
    public void Translations_Placeholders_MatchTheEnglishText()
    {
        foreach (var (english, pt) in Translations.All)
        {
            Placeholders(pt).ShouldBe(Placeholders(english), english);
            pt.ShouldNotBeNullOrWhiteSpace();
        }
    }

    [SkippableTheory]
    [InlineData("pt-BR", "O documento está certificado com DocMDP P=1")]
    [InlineData("es", "The document is certified with DocMDP P=1")]
    [InlineData("en-US", "The document is certified with DocMDP P=1")]
    [InlineData("fr-FR", "The document is certified with DocMDP P=1")]
    public async Task Evaluate_UiCulture_ReturnsTextInThatLanguage(string culture, string expectedStart)
    {
        var previous = CultureInfo.CurrentUICulture;
        CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(culture);
        try
        {
            var facts = await fixture.Documents.FactsAsync(DocumentStore.SampleKey("certified-p1"));
            var report = Compatibility.Evaluate(new SigningOptions(), facts, null);

            report.Issues.ShouldContain(i => i.Message.StartsWith(expectedStart, StringComparison.Ordinal));
        }
        finally
        {
            CultureInfo.CurrentUICulture = previous;
        }
    }

    [SkippableTheory]
    [InlineData("pt-PT", "pt-BR")]
    [InlineData("es-AR", "en-US")]
    [InlineData("de-DE", "en-US")]
    public void Language_Culture_MapsToSupportedLanguage(string culture, string expected) =>
        L.Language(CultureInfo.GetCultureInfo(culture)).ShouldBe(expected);

    private static string[] Placeholders(string text) => [.. Placeholder().Matches(text).Select(m => m.Groups[1].Value).Order(StringComparer.Ordinal)];

    private static string RepositoryRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "SimpleSign.sln")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new DirectoryNotFoundException("SimpleSign.sln not found above the test output.");
    }

    [GeneratedRegex(@"L\.T\(\s*""((?:[^""\\]|\\.)*)""")]
    private static partial Regex TCall();

    [GeneratedRegex(@"\{(\d+)(?::[^}]*)?\}")]
    private static partial Regex Placeholder();
}
