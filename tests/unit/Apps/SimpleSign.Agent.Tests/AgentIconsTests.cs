using Avalonia.Headless.XUnit;
using Shouldly;
using SimpleSign.Agent.Services;
using SimpleSign.Agent.Views;

namespace SimpleSign.Agent.Tests;

[Trait("Category", "Unit")]
public sealed class AgentIconsTests
{
    [AvaloniaFact]
    public void Export_WritesTheApplicationAndTrayIcons()
    {
        string directory = Directory.CreateTempSubdirectory("simplesign-agent-icons-").FullName;

        AgentIcons.Export(directory);

        byte[] png = File.ReadAllBytes(Path.Combine(directory, "icon-1024.png"));
        png[..4].ShouldBe([0x89, (byte)'P', (byte)'N', (byte)'G']);
        byte[] ico = File.ReadAllBytes(Path.Combine(directory, "icon.ico"));
        ico[..4].ShouldBe([0, 0, 1, 0]);
        BitConverter.ToInt16(ico, 4).ShouldBe((short)7);
        foreach (var state in Enum.GetValues<AgentState>())
        {
            File.Exists(Path.Combine(directory, $"tray-template-{state.ToString().ToLowerInvariant()}.png")).ShouldBeTrue();
            AgentIcons.Tray(state).ShouldNotBeNull();
        }
    }

    [Fact]
    public void Ico_DirectoryPointsAtEachImage()
    {
        byte[] first = [1, 2, 3];
        byte[] second = [4, 5];

        byte[] ico = AgentIcons.Ico([(16, first), (256, second)]);

        ico.Length.ShouldBe(6 + 32 + 5);
        ico[6].ShouldBe((byte)16);
        ico[22].ShouldBe((byte)0);
        BitConverter.ToInt32(ico, 6 + 8).ShouldBe(3);
        BitConverter.ToInt32(ico, 6 + 12).ShouldBe(38);
        BitConverter.ToInt32(ico, 22 + 12).ShouldBe(41);
        ico[38..41].ShouldBe(first);
    }
}
