using Shouldly;
using SimpleSign.Agent.Docs;
using SimpleSign.Agent.Localization;

namespace SimpleSign.Agent.Tests;

[Trait("Category", "Unit")]
public sealed class DocLibraryTests
{
    public static TheoryData<string, string> TopicsAndLanguages()
    {
        var data = new TheoryData<string, string>();
        foreach (string topic in DocLibrary.Topics)
        {
            data.Add(topic, L.English);
            data.Add(topic, L.Portuguese);
            data.Add(topic, L.Spanish);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(TopicsAndLanguages))]
    public void Load_EveryTopicInEveryLanguage_ParsesAndStartsWithItsTitle(string topic, string language)
    {
        string text = DocLibrary.Load(topic, language, 21590);

        text.ShouldNotContain("{port}");
        var blocks = Markdown.Parse(text);
        blocks[0].ShouldBeOfType<MdHeading>().Level.ShouldBe(1);
        blocks.Count.ShouldBeGreaterThan(4);
        Strings.For(language).ShouldContainKey("docs.topic." + topic);
    }

    [Theory]
    [MemberData(nameof(TopicsAndLanguages))]
    public void Load_LinksToOtherTopics_Exist(string topic, string language)
    {
        var links = Markdown.Parse(DocLibrary.Load(topic, language, 21590))
            .SelectMany(b => b switch
            {
                MdParagraph p => p.Inlines,
                MdNote n => n.Inlines,
                MdList l => l.Items.SelectMany(i => i),
                _ => [],
            })
            .Where(i => i.Style == MdStyle.Link && i.Url!.StartsWith('#'));

        foreach (var link in links)
        {
            DocLibrary.Topics.ShouldContain(link.Url![1..]);
        }
    }

    [Fact]
    public void Load_EveryLanguage_HasTheSameStructure()
    {
        foreach (string topic in DocLibrary.Topics)
        {
            var english = Markdown.Parse(DocLibrary.Load(topic, L.English, 1));
            foreach (string language in new[] { L.Portuguese, L.Spanish })
            {
                Markdown.Parse(DocLibrary.Load(topic, language, 1))
                    .Select(b => b.GetType().Name)
                    .ShouldBe(english.Select(b => b.GetType().Name), $"{topic} {language}");
            }
        }
    }

    [Fact]
    public void Load_ThePort_ReplacesThePlaceholder() =>
        DocLibrary.Load("integration", L.English, 31999).ShouldContain("http://127.0.0.1:31999");
}
