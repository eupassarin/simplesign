using System.Globalization;
using System.Text.RegularExpressions;
using Shouldly;
using SimpleSign.Agent.Localization;

namespace SimpleSign.Agent.Tests;

[Trait("Category", "Unit")]
public sealed partial class StringsTests
{
    public static TheoryData<string> Translations() => new(L.Portuguese, L.Spanish);

    [Theory]
    [MemberData(nameof(Translations))]
    public void EveryTranslation_HasTheSameKeysAsEnglish(string language) =>
        Strings.For(language).Keys.Order(StringComparer.Ordinal).ShouldBe(Strings.English.Keys.Order(StringComparer.Ordinal));

    [Theory]
    [MemberData(nameof(Translations))]
    public void EveryTranslation_HasTheSamePlaceholdersAsEnglish(string language)
    {
        var texts = Strings.For(language);
        foreach (var (key, english) in Strings.English)
        {
            Placeholders(texts[key]).ShouldBe(Placeholders(english), $"{language} {key}");
        }
    }

    [Fact]
    public void EveryText_IsFilledIn()
    {
        foreach (var texts in new[] { Strings.English, Strings.Portuguese, Strings.Spanish })
        {
            texts.Where(t => string.IsNullOrWhiteSpace(t.Value)).Select(t => t.Key).ShouldBeEmpty();
        }
    }

    [Fact]
    public void Languages_AreTheThreeWithADictionaryEach()
    {
        L.Languages.Select(l => l.Id).ShouldBe([L.English, L.Portuguese, L.Spanish]);
        L.Languages.Select(l => Strings.For(l.Id)).ShouldBeUnique();
    }

    [Fact]
    public void Use_Spanish_SwitchesTheTexts()
    {
        try
        {
            L.Use(L.Spanish);

            L.Language.ShouldBe(L.Spanish);
            L.T("common.cancel").ShouldBe(Strings.Spanish["common.cancel"]);
        }
        finally
        {
            L.Use(L.English);
        }
    }

    [Fact]
    public void EveryKeyUsedInTheCode_Exists()
    {
        string source = Path.Combine(RepositoryRoot(), "src", "Apps", "SimpleSign.Agent");
        var used = Directory.EnumerateFiles(source, "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                && !f.EndsWith("Strings.cs", StringComparison.Ordinal))
            .SelectMany(f => KeyInCode().Matches(File.ReadAllText(f)).Select(m => m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value))
            .Distinct(StringComparer.Ordinal)
            .ToList();

        used.Count.ShouldBeGreaterThan(100);
        used.Where(k => !Strings.English.ContainsKey(k)).ShouldBeEmpty();
    }

    [Theory]
    [InlineData("pt-BR", "pt-BR")]
    [InlineData("pt-PT", "pt-BR")]
    [InlineData("en-GB", "en-US")]
    [InlineData("es-ES", "es-ES")]
    [InlineData("es-PE", "es-ES")]
    [InlineData("es-MX", "es-ES")]
    [InlineData("fr-FR", "en-US")]
    public void Detect_PortugueseSpanishOrEnglish(string culture, string expected) =>
        L.Detect(CultureInfo.GetCultureInfo(culture)).ShouldBe(expected);

    private static string[] Placeholders(string text) =>
        [.. Placeholder().Matches(text).Select(m => m.Value).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)];

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "SimpleSign.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new DirectoryNotFoundException("SimpleSign.sln");
    }

    [GeneratedRegex(@"\{\d+\}")]
    private static partial Regex Placeholder();

    // L.T("key"…) and the keys picked by a condition: L.T(x ? "a.b" : "c.d").
    [GeneratedRegex("""L\.T\((?:[^"()]*\? )?"([a-z]+(?:\.[A-Za-z]+)+)"|: "([a-z]+(?:\.[A-Za-z]+)+)"\)""")]
    private static partial Regex KeyInCode();
}
