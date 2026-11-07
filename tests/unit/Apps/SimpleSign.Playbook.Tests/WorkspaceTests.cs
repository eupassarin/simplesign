using Shouldly;
using SimpleSign.Playbook.Workspaces;

namespace SimpleSign.Playbook.Tests;

[Trait("Category", "Unit")]
public sealed class WorkspaceTests : IDisposable
{
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "simplesign-workspace-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_folder))
        {
            Directory.Delete(_folder, recursive: true);
        }
    }

    [Fact]
    public void Create_Starter_IsAValidPlaybookWithAGitIgnore()
    {
        var workspace = Workspace.Create(_folder, "My checks");

        var (playbook, issues) = workspace.LoadPlaybook();
        playbook.ShouldNotBeNull().Name.ShouldBe("My checks");
        issues.Where(i => i.IsError).ShouldBeEmpty();
        File.ReadAllText(Path.Combine(_folder, ".gitignore")).ShouldContain("secrets.json");
        Workspace.Open(_folder).Directory.ShouldBe(Path.GetFullPath(_folder));
    }

    [Fact]
    public void Create_FromSample_CopiesItsFiles()
    {
        string sample = Path.Combine(AppContext.BaseDirectory, "Samples", "sandbox-basics");

        var workspace = Workspace.Create(_folder, "ignored", sample);

        workspace.LoadPlaybook().Playbook!.Name.ShouldBe("Sandbox basics");
        workspace.Assets().ShouldContain(a => a.Path == "assets/contract.html");
    }

    [Fact]
    public void Create_ExistingPlaybook_Throws()
    {
        Workspace.Create(_folder, "a");

        Should.Throw<IOException>(() => Workspace.Create(_folder, "b"));
    }

    [Fact]
    public void Open_FolderWithoutPlaybook_Throws()
    {
        Directory.CreateDirectory(_folder);

        Should.Throw<FileNotFoundException>(() => Workspace.Open(_folder));
    }

    [Fact]
    public void SavePlaybookText_WithErrors_IsKeptAndReported()
    {
        var workspace = Workspace.Create(_folder, "a");

        var issues = workspace.SavePlaybookText("{ \"name\": \"\" }");

        workspace.ReadPlaybookText().ShouldBe("{ \"name\": \"\" }");
        issues.ShouldContain(i => i.Path == "name");
    }

    [Fact]
    public void Secrets_SetAndRemove()
    {
        var workspace = Workspace.Create(_folder, "a");

        workspace.SetSecret("a1", "1234");
        workspace.ReadSecrets()["a1"].ShouldBe("1234");
        workspace.SetSecret("a1", null);
        workspace.ReadSecrets().ShouldBeEmpty();
    }

    [Fact]
    public void Assets_SaveDeleteAndStayInside()
    {
        var workspace = Workspace.Create(_folder, "a");

        workspace.SaveAsset("../../evil.pfx", [1]).ShouldBe("assets/evil.pfx");
        workspace.Assets().ShouldHaveSingleItem().Path.ShouldBe("assets/evil.pfx");
        workspace.DeleteAsset("playbook.json").ShouldBeFalse();
        workspace.DeleteAsset("assets/evil.pfx").ShouldBeTrue();
        Should.Throw<ArgumentException>(() => workspace.Resolve("../outside"));
    }
}
