using Shouldly;
using Xunit;

namespace SimpleSign.Contracts.Tests;

/// <summary>
/// Contract tests for the release packaging: every packable project under <c>src/</c> must be
/// packed and pushed by <c>.github/workflows/release.yml</c>, and must carry the metadata
/// NuGet.org shows. The pack list is hand-written, so a new package is otherwise simply left
/// out of the release — as <c>SimpleSign.Europe.Eidas</c> was from 0.11.0.
/// </summary>
[Trait("Category", "Contract")]
public sealed class ReleasePackagingContractTests
{
    [Fact]
    public void ReleaseWorkflow_PacksEveryPackableProject()
    {
        string root = RepositoryRoot();
        string workflow = File.ReadAllText(Path.Combine(root, ".github", "workflows", "release.yml"));

        IReadOnlyList<string> missing = [.. PackableProjects(root)
            .Where(p => !workflow.Contains(RelativePath(root, p), StringComparison.Ordinal))
            .Select(Path.GetFileNameWithoutExtension)
            .OfType<string>()
            .Order()];

        missing.ShouldBeEmpty(
            $"these packable projects are not in the pack list of release.yml: {string.Join(", ", missing)}");
    }

    [Fact]
    public void EveryPackableProject_HasADescriptionAndAPackageReadme()
    {
        string root = RepositoryRoot();

        foreach (string project in PackableProjects(root))
        {
            string xml = File.ReadAllText(project);
            string name = Path.GetFileNameWithoutExtension(project);

            xml.ShouldContain("<Description>", Case.Sensitive, $"{name} has no <Description> for NuGet.org");
            File.Exists(Path.Combine(Path.GetDirectoryName(project)!, "PACKAGE.md"))
                .ShouldBeTrue($"{name} has no PACKAGE.md (Directory.Build.props declares it as the readme)");
        }
    }

    private static IEnumerable<string> PackableProjects(string root) =>
        Directory.EnumerateFiles(Path.Combine(root, "src"), "*.csproj", SearchOption.AllDirectories)
            .Where(p => !File.ReadAllText(p).Contains("<IsPackable>false</IsPackable>", StringComparison.Ordinal))
            .Order(StringComparer.Ordinal);

    private static string RelativePath(string root, string path) =>
        Path.GetRelativePath(root, path).Replace(Path.DirectorySeparatorChar, '/');

    private static string RepositoryRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);

        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "SimpleSign.sln")))
        {
            directory = directory.Parent;
        }

        directory.ShouldNotBeNull("the repository root (the folder holding SimpleSign.sln) was not found");
        return directory.FullName;
    }
}
