using System.IO.Compression;
using System.Text.Json;

namespace SimpleSign.Playbook.Runs;

/// <summary>The runs of a workspace, one folder each under runs/.</summary>
public static class RunStore
{
    public const string RunFile = "run.json";

    /// <summary>Writes run.json (atomically).</summary>
    public static void Save(string runFolder, RunRecord run)
    {
        Directory.CreateDirectory(runFolder);
        string path = Path.Combine(runFolder, RunFile);
        string temp = path + ".tmp";
        System.IO.File.WriteAllText(temp, JsonSerializer.Serialize(run, RunJson.Default.RunRecord));
        System.IO.File.Move(temp, path, overwrite: true);
    }

    /// <summary>The run kept in <paramref name="runFolder"/>, or null.</summary>
    public static RunRecord? Load(string runFolder)
    {
        string path = Path.Combine(runFolder, RunFile);
        try
        {
            return System.IO.File.Exists(path) ? JsonSerializer.Deserialize(System.IO.File.ReadAllText(path), RunJson.Default.RunRecord) : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>The runs of the workspace, newest first.</summary>
    public static IReadOnlyList<RunListItem> List(string runsFolder)
    {
        if (!Directory.Exists(runsFolder))
        {
            return [];
        }

        return [.. Directory.EnumerateDirectories(runsFolder)
            .Select(Load)
            .OfType<RunRecord>()
            .OrderByDescending(r => r.StartedAt)
            .Select(r => new RunListItem(r.Id, r.PlaybookName, r.StartedAt, r.FinishedAt, r.Status, r.Summary))];
    }

    /// <summary>
    /// The folder of the run <paramref name="id"/>, found among the runs folder's own subfolders: the
    /// id is only compared, never used to build a path, so it cannot point anywhere else.
    /// </summary>
    /// <exception cref="ArgumentException">The id is not a run id.</exception>
    /// <exception cref="DirectoryNotFoundException">There is no such run.</exception>
    public static string Folder(string runsFolder, string id)
    {
        if (string.IsNullOrWhiteSpace(id) || id.Contains('/', StringComparison.Ordinal) || id.Contains('\\', StringComparison.Ordinal) || id.Contains("..", StringComparison.Ordinal))
        {
            throw new ArgumentException($"'{id}' is not a run id.", nameof(id));
        }

        return (Directory.Exists(runsFolder)
                ? Directory.EnumerateDirectories(runsFolder).FirstOrDefault(d => string.Equals(Path.GetFileName(d), id, StringComparison.Ordinal))
                : null)
            ?? throw new DirectoryNotFoundException($"No run '{id}'.");
    }

    /// <summary>
    /// A file of a run (a step's output, an attachment, a report), found among the run folder's own
    /// files by its relative path: the requested path is only compared, never opened.
    /// </summary>
    public static string? FileOf(string runFolder, string relative)
    {
        string wanted = relative.Replace('\\', '/');
        return Directory.Exists(runFolder)
            ? Directory.EnumerateFiles(runFolder, "*", SearchOption.AllDirectories)
                .FirstOrDefault(f => string.Equals(Path.GetRelativePath(runFolder, f).Replace('\\', '/'), wanted, StringComparison.Ordinal))
            : null;
    }

    /// <summary>The whole run folder as a zip.</summary>
    public static byte[] Zip(string runFolder)
    {
        using var buffer = new MemoryStream();
        using (var zip = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (string file in Directory.EnumerateFiles(runFolder, "*", SearchOption.AllDirectories))
            {
                zip.CreateEntryFromFile(file, Path.GetRelativePath(runFolder, file).Replace('\\', '/'), CompressionLevel.Optimal);
            }
        }

        return buffer.ToArray();
    }
}
