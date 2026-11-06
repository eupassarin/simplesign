using System.Xml.Linq;
using Shouldly;
using SimpleSign.Agent.Services;

namespace SimpleSign.Agent.Tests;

[Trait("Category", "Unit")]
public class LoginItemTests
{
    [Fact]
    public void LaunchAgentPlist_PathWithXmlCharacters_IsEscapedAndRunsAtLoad()
    {
        string plist = LoginItem.LaunchAgentPlist("/Applications/A & B <x>.app/Contents/MacOS/SimpleSign.Agent");

        var doc = XDocument.Parse(plist);
        var values = doc.Descendants("string").Select(e => e.Value).ToList();
        values.ShouldContain("io.github.eupassarin.simplesign.agent");
        values.ShouldContain("/Applications/A & B <x>.app/Contents/MacOS/SimpleSign.Agent");
        doc.Descendants("key").Select(e => e.Value).ShouldContain("RunAtLoad");
        doc.Descendants("key").Select(e => e.Value).ShouldNotContain("KeepAlive");
    }

    [Fact]
    public void AutostartEntry_PathWithSpacesAndQuotes_IsQuoted()
    {
        string entry = LoginItem.AutostartEntry("/opt/simple sign/\"agent\"");

        entry.ShouldStartWith("[Desktop Entry]");
        entry.ShouldContain("Exec=\"/opt/simple sign/\\\"agent\\\"\"");
        entry.ShouldContain("Type=Application");
    }
}
