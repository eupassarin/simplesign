using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SimpleSign.Playbook.Model;

namespace SimpleSign.Playbook.Workspaces;

/// <summary>A file of the workspace's assets folder.</summary>
public sealed record AssetFile(string Path, long Bytes, DateTimeOffset Modified);

/// <summary>
/// A workspace: a folder with <c>playbook.json</c>, <c>assets/</c>, <c>secrets.json</c> (the passwords
/// of the assets, kept out of the playbook so it can be shared) and <c>runs/</c>. It can be versioned;
/// <c>secrets.json</c> and <c>runs/</c> are best left out (a .gitignore is written).
/// </summary>
public sealed class Workspace
{
    public const string PlaybookFile = "playbook.json";
    public const string SecretsFile = "secrets.json";
    public const string AssetsFolder = "assets";
    public const string RunsFolder = "runs";

    private readonly Lock _gate = new();

    private Workspace(string directory)
    {
        Directory = directory;
    }

    /// <summary>The folder (full path).</summary>
    public string Directory { get; }

    public string PlaybookPath => Path.Combine(Directory, PlaybookFile);

    public string RunsPath => Path.Combine(Directory, RunsFolder);

    /// <summary>Opens a folder that has a playbook.json.</summary>
    /// <exception cref="DirectoryNotFoundException">The folder does not exist.</exception>
    /// <exception cref="FileNotFoundException">It has no playbook.json.</exception>
    public static Workspace Open(string directory)
    {
        string full = Path.GetFullPath(directory);
        if (!System.IO.Directory.Exists(full))
        {
            throw new DirectoryNotFoundException($"The folder '{full}' does not exist.");
        }

        if (!File.Exists(Path.Combine(full, PlaybookFile)))
        {
            throw new FileNotFoundException($"The folder '{full}' has no {PlaybookFile}.", Path.Combine(full, PlaybookFile));
        }

        return new Workspace(full);
    }

    /// <summary>Creates a workspace in an empty (or new) folder, with a starter playbook or a copy of <paramref name="template"/>.</summary>
    /// <exception cref="IOException">The folder already has a playbook.json.</exception>
    public static Workspace Create(string directory, string name, string? template = null)
    {
        string full = Path.GetFullPath(directory);
        if (File.Exists(Path.Combine(full, PlaybookFile)))
        {
            throw new IOException($"The folder '{full}' already has a {PlaybookFile}.");
        }

        System.IO.Directory.CreateDirectory(Path.Combine(full, AssetsFolder));
        if (template is not null)
        {
            CopyFolder(template, full);
        }
        else
        {
            var starter = new PlaybookDefinition
            {
                Name = name,
                Description = "Describe what this playbook checks.",
                Sections = [new SectionDefinition { Id = "first", Title = "First section", Steps = [new StepDefinition
                {
                    Id = "version",
                    Title = "The CLI answers",
                    Description = "simplesign version prints its version.",
                    Run = new RunDefinition { Args = ["version"], Network = "none" },
                    Expect = new Expectation { ExitCode = 0 },
                }] }],
            };
            File.WriteAllText(Path.Combine(full, PlaybookFile), JsonSerializer.Serialize(starter, PlaybookJson.Default.PlaybookDefinition));
        }

        string ignore = Path.Combine(full, ".gitignore");
        if (!File.Exists(ignore))
        {
            File.WriteAllText(ignore, $"{SecretsFile}\n{RunsFolder}/\n");
        }

        return new Workspace(full);
    }

    /// <summary>The playbook's text, as written.</summary>
    public string ReadPlaybookText()
    {
        lock (_gate)
        {
            return File.ReadAllText(PlaybookPath);
        }
    }

    /// <summary>Parses the playbook and checks it, assets included.</summary>
    public (PlaybookDefinition? Playbook, IReadOnlyList<PlaybookIssue> Issues) LoadPlaybook()
    {
        var (playbook, issues) = PlaybookValidator.Parse(ReadPlaybookText());
        return playbook is null ? (null, issues) : (playbook, PlaybookValidator.Validate(playbook, Directory));
    }

    /// <summary>Saves the playbook's text (even with issues, so work is not lost) and returns its issues.</summary>
    public IReadOnlyList<PlaybookIssue> SavePlaybookText(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        lock (_gate)
        {
            string temp = PlaybookPath + ".tmp";
            File.WriteAllText(temp, json);
            File.Move(temp, PlaybookPath, overwrite: true);
        }

        return LoadPlaybook().Issues;
    }

    /// <summary>The SHA-256 of the playbook's text, recorded with each run.</summary>
    public string PlaybookHash() => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(ReadPlaybookText())));

    /// <summary>The files of assets/.</summary>
    public IReadOnlyList<AssetFile> Assets()
    {
        string folder = Path.Combine(Directory, AssetsFolder);
        if (!System.IO.Directory.Exists(folder))
        {
            return [];
        }

        return [.. System.IO.Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories)
            .Select(f => new FileInfo(f))
            .Select(f => new AssetFile(Path.GetRelativePath(Directory, f.FullName).Replace('\\', '/'), f.Length, f.LastWriteTimeUtc))
            .OrderBy(f => f.Path, StringComparer.Ordinal)];
    }

    /// <summary>Writes an uploaded file to assets/ and returns its path in the workspace.</summary>
    public string SaveAsset(string fileName, byte[] content)
    {
        string name = Path.GetFileName(fileName);
        if (string.IsNullOrWhiteSpace(name) || name is "." or "..")
        {
            throw new ArgumentException("The file needs a name.", nameof(fileName));
        }

        string folder = Path.Combine(Directory, AssetsFolder);
        System.IO.Directory.CreateDirectory(folder);
        File.WriteAllBytes(Path.Combine(folder, name), content);
        return $"{AssetsFolder}/{name}";
    }

    /// <summary>
    /// Deletes a file of assets/, found among the folder's own files by its workspace path (such as
    /// assets/a1.pfx): the requested path is only compared, never opened.
    /// </summary>
    public bool DeleteAsset(string path)
    {
        string folder = Path.Combine(Directory, AssetsFolder);
        string wanted = path.Replace('\\', '/');
        string? file = System.IO.Directory.Exists(folder)
            ? System.IO.Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories)
                .FirstOrDefault(f => string.Equals(Path.GetRelativePath(Directory, f).Replace('\\', '/'), wanted, StringComparison.Ordinal))
            : null;
        if (file is null)
        {
            return false;
        }

        File.Delete(file);
        return true;
    }

    /// <summary>The full path of a workspace-relative path; refuses anything outside the workspace.</summary>
    /// <exception cref="ArgumentException">The path leaves the workspace.</exception>
    public string Resolve(string relative)
    {
        string full = Path.GetFullPath(Path.Combine(Directory, relative));
        if (!full.StartsWith(Directory + Path.DirectorySeparatorChar, StringComparison.Ordinal) && full != Directory)
        {
            throw new ArgumentException($"'{relative}' is outside the workspace.", nameof(relative));
        }

        return full;
    }

    /// <summary>The secrets (asset passwords), by key.</summary>
    public Dictionary<string, string> ReadSecrets()
    {
        lock (_gate)
        {
            string path = Path.Combine(Directory, SecretsFile);
            return File.Exists(path)
                ? JsonSerializer.Deserialize(File.ReadAllText(path), PlaybookJson.Default.DictionaryStringString) ?? []
                : [];
        }
    }

    /// <summary>Sets a secret; null removes it.</summary>
    public void SetSecret(string key, string? value)
    {
        lock (_gate)
        {
            var secrets = ReadSecretsUnlocked();
            if (value is null)
            {
                secrets.Remove(key);
            }
            else
            {
                secrets[key] = value;
            }

            File.WriteAllText(Path.Combine(Directory, SecretsFile), JsonSerializer.Serialize(secrets, PlaybookJson.Default.DictionaryStringString));
        }
    }

    private Dictionary<string, string> ReadSecretsUnlocked()
    {
        string path = Path.Combine(Directory, SecretsFile);
        return File.Exists(path) ? JsonSerializer.Deserialize(File.ReadAllText(path), PlaybookJson.Default.DictionaryStringString) ?? [] : [];
    }

    private static void CopyFolder(string from, string to)
    {
        foreach (string file in System.IO.Directory.EnumerateFiles(from, "*", SearchOption.AllDirectories))
        {
            string target = Path.Combine(to, Path.GetRelativePath(from, file));
            System.IO.Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target, overwrite: false);
        }
    }
}
