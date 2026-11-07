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

    /// <summary>The run folder of <paramref name="id"/>; refuses ids that would leave the runs folder.</summary>
    public static string Folder(string runsFolder, string id)
    {
        if (string.IsNullOrWhiteSpace(id) || id.Contains('/', StringComparison.Ordinal) || id.Contains('\\', StringComparison.Ordinal) || id.Contains("..", StringComparison.Ordinal))
        {
            throw new ArgumentException($"'{id}' is not a run id.", nameof(id));
        }

        return Path.Combine(runsFolder, id);
    }

    /// <summary>A file of a run (a step's output, an attachment, a report); refuses paths that leave the run folder.</summary>
    public static string? FileOf(string runFolder, string relative)
    {
        string full = Path.GetFullPath(Path.Combine(runFolder, relative));
        return full.StartsWith(Path.GetFullPath(runFolder) + Path.DirectorySeparatorChar, StringComparison.Ordinal) && System.IO.File.Exists(full) ? full : null;
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
