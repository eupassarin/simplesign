using Shouldly;
using SimpleSign.Playbook.Runs;

namespace SimpleSign.Playbook.Tests;

[Trait("Category", "Unit")]
public sealed class RunStoreTests : IDisposable
{
    private readonly string _runs = Path.Combine(Path.GetTempPath(), "simplesign-runs-" + Guid.NewGuid().ToString("N"));

    public RunStoreTests()
    {
        Directory.CreateDirectory(Path.Combine(_runs, "20260101-000000-abcd", "steps", "s"));
        File.WriteAllText(Path.Combine(_runs, "20260101-000000-abcd", "steps", "s", "stdout.txt"), "ok");
        File.WriteAllText(Path.Combine(_runs, "secret.txt"), "outside the run");
    }

    public void Dispose() => Directory.Delete(_runs, recursive: true);

    [Fact]
    public void Folder_ExistingRun_IsFound() =>
        RunStore.Folder(_runs, "20260101-000000-abcd").ShouldBe(Path.Combine(_runs, "20260101-000000-abcd"));

    [Fact]
    public void Folder_UnknownRun_IsNotFound() =>
        Should.Throw<DirectoryNotFoundException>(() => RunStore.Folder(_runs, "20990101-000000-zzzz"));

    [Theory]
    [InlineData("../outside")]
    [InlineData("a/b")]
    [InlineData("")]
    public void Folder_NotARunId_IsRefused(string id) =>
        Should.Throw<ArgumentException>(() => RunStore.Folder(_runs, id));

    [Fact]
    public void FileOf_FileOfTheRun_IsFound()
    {
        string folder = RunStore.Folder(_runs, "20260101-000000-abcd");

        File.ReadAllText(RunStore.FileOf(folder, "steps/s/stdout.txt").ShouldNotBeNull()).ShouldBe("ok");
    }

    [Theory]
    [InlineData("../secret.txt")]
    [InlineData("steps/s/../../../secret.txt")]
    [InlineData("steps/s/missing.txt")]
    public void FileOf_OutsideOrMissing_IsNull(string path) =>
        RunStore.FileOf(RunStore.Folder(_runs, "20260101-000000-abcd"), path).ShouldBeNull();
}
