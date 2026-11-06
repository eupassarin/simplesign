using System.Globalization;
using System.Text.RegularExpressions;
using Shouldly;
using SimpleSign.Signers.Cloud.Psc;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Localization;
using SimpleSign.TestBench.Sandbox;
using SimpleSign.TestBench.Signing;

namespace SimpleSign.TestBench.Tests;

/// <summary>Every text the backend shows has its pt-BR and es versions, with the same placeholders.</summary>
[Collection(TestBenchCollection.Name)]
[Trait("Category", "Unit")]
public sealed partial class LocalizationTests(TestBenchFixture fixture)
{
    [Fact]
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

    [Fact]
    public void Translations_CatalogSamplesAndSandbox_AreTranslated()
    {
        var texts = OptionCatalog.All.Values.SelectMany(i => new[] { i.Title, i.Summary, i.Details })
            .Concat(fixture.Documents.Samples.SelectMany(s => new[] { s.Title, s.Description }))
            .Concat(fixture.Sandbox.Pki.Signers.SelectMany(s => new[] { s.Title, s.Description, s.Problem }))
            .Concat(fixture.Sandbox.Csc.Credentials.Select(c => c.Description))
            .Concat(fixture.ValidationSamples.SelectMany(s => new[] { s.Title, s.Description }))
            .Concat(fixture.CadesSamples.SelectMany(s => new[] { s.Title, s.Description }))
            .Concat(fixture.XmlSamples.SelectMany(s => new[] { s.Title, s.Description }))
            .OfType<string>();

        texts.Where(t => !Translations.All.ContainsKey(t)).ShouldBeEmpty();
    }

    [Fact]
    public async Task Translations_CredentialNotes_AreTranslated()
    {
        var handles = new List<CredentialHandle>
        {
            fixture.Factory.OpenSandbox(new SandboxCredentialRequest("expired")),
            await fixture.Factory.OpenPscPasswordAsync(new PscCredentialRequest(null, null, null, null, SandboxPsc.Otp, PscScope.SingleSignature, "maria-rsa2048"), EnvironmentMode.Sandbox, default),
            await fixture.Factory.OpenCscAsync(new CscCredentialRequest(null, CscServiceAuth.Token, null, null, null, "rsa-scal1", CscAuthorizerKind.Explicit, SandboxCsc.Pin, null), EnvironmentMode.Sandbox, default),
        };

        handles.SelectMany(h => h.Notes).Select(n => n.English).Where(t => !Translations.All.ContainsKey(t)).ShouldBeEmpty();
    }

    [Fact]
    public void Translations_Placeholders_MatchTheEnglishText()
    {
        foreach (var (english, (pt, es)) in Translations.All)
        {
            var expected = Placeholders(english);
            Placeholders(pt).ShouldBe(expected, english);
            Placeholders(es).ShouldBe(expected, english);
            pt.ShouldNotBeNullOrWhiteSpace();
            es.ShouldNotBeNullOrWhiteSpace();
        }
    }

    [Theory]
    [InlineData("pt-BR", "O documento está certificado com DocMDP P=1")]
    [InlineData("es", "El documento está certificado con DocMDP P=1")]
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

    [Theory]
    [InlineData("pt-PT", "pt-BR")]
    [InlineData("es-AR", "es")]
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
