namespace SimpleSign.Integration.Tests.Helpers;

/// <summary>
/// Resolves paths to test fixture PDFs.
/// </summary>
internal static class FixturePath
{
    private const string Dir = "Fixtures";

    public static string Get(string fileName) => Path.Combine(Dir, fileName);

    public static bool Exists(string fileName) => File.Exists(Get(fileName));

    public static Stream Open(string fileName) => File.OpenRead(Get(fileName));

    public static Task<byte[]> ReadBytesAsync(string fileName)
        => File.ReadAllBytesAsync(Get(fileName));
}
