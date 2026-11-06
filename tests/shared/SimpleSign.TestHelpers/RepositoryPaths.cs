namespace SimpleSign.TestHelpers;

/// <summary>
/// Paths inside the repository, found from the directory that holds <c>SimpleSign.sln</c>, so a
/// test does not depend on how deep its project sits under <c>tests/</c>.
/// </summary>
public static class RepositoryPaths
{
    private static readonly Lazy<string> RootPath = new(FindRoot);

    /// <summary>The repository root (the directory that contains <c>SimpleSign.sln</c>).</summary>
    public static string Root => RootPath.Value;

    /// <summary>A path under the repository root.</summary>
    /// <param name="parts">The path segments, from the root.</param>
    public static string Get(params string[] parts) => Path.Combine([Root, .. parts]);

    /// <summary>A file in <c>tests/integration/SimpleSign.Integration.Tests/Fixtures</c>.</summary>
    /// <param name="fileName">The fixture file name.</param>
    public static string IntegrationFixture(string fileName) =>
        Get("tests", "integration", "SimpleSign.Integration.Tests", "Fixtures", fileName);

    private static string FindRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Combine(dir.FullName, "SimpleSign.sln")))
            {
                return dir.FullName;
            }
        }

        throw new DirectoryNotFoundException($"SimpleSign.sln not found above {AppContext.BaseDirectory}");
    }
}
