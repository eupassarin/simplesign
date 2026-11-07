using System.Text.Json;
using System.Text.Json.Serialization;

namespace SimpleSign.Playbook.Workspaces;

/// <summary>
/// This machine's settings (not the playbook's): how to start the SimpleSign CLI, and the workspaces
/// opened lately. Kept in %LocalAppData%/SimpleSign/Playbook/settings.json.
/// </summary>
public sealed record AppSettings
{
    /// <summary>The program: "simplesign" (on the PATH), a path to the CLI, or "dotnet".</summary>
    public string? CliCommand { get; set; }

    /// <summary>Arguments put before each step's own, such as ["run", "--project", "src/Apps/SimpleSign.Cli", "--"] with "dotnet".</summary>
    public List<string> CliPrefix { get; set; } = [];

    /// <summary>The workspaces opened lately, newest first.</summary>
    public List<string> RecentWorkspaces { get; set; } = [];
}

/// <summary>Reads and writes <see cref="AppSettings"/>, and finds the CLI when none is set.</summary>
public sealed class AppSettingsStore
{
    private readonly string _path;
    private readonly Lock _gate = new();

    public AppSettingsStore(string? directory = null)
    {
        string folder = directory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SimpleSign", "Playbook");
        _path = Path.Combine(folder, "settings.json");
    }

    public AppSettings Read()
    {
        lock (_gate)
        {
            try
            {
                return File.Exists(_path) ? JsonSerializer.Deserialize(File.ReadAllText(_path), SettingsJson.Default.AppSettings) ?? new() : new();
            }
            catch (JsonException)
            {
                return new();
            }
        }
    }

    public AppSettings Write(AppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        lock (_gate)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            File.WriteAllText(_path, JsonSerializer.Serialize(settings, SettingsJson.Default.AppSettings));
            return settings;
        }
    }

    /// <summary>Puts <paramref name="workspace"/> first in the recent list (ten at most).</summary>
    public void Remember(string workspace)
    {
        var settings = Read();
        var recent = settings.RecentWorkspaces.Where(w => !string.Equals(w, workspace, StringComparison.Ordinal)).Prepend(workspace).Take(10).ToList();
        Write(settings with { RecentWorkspaces = recent });
    }

    /// <summary>
    /// The program and prefix that start the CLI: the settings when set; otherwise a CLI built in this
    /// repository (src/Apps/SimpleSign.Cli/bin, the newest); otherwise "simplesign" on the PATH.
    /// </summary>
    public (string Program, IReadOnlyList<string> Prefix) ResolveCli()
    {
        var settings = Read();
        if (!string.IsNullOrWhiteSpace(settings.CliCommand))
        {
            return (settings.CliCommand, settings.CliPrefix);
        }

        return (FindBuiltCli() ?? "simplesign", []);
    }

    /// <summary>The newest simplesign binary built in the repository this app runs from, if any.</summary>
    internal static string? FindBuiltCli()
    {
        string exe = OperatingSystem.IsWindows() ? "simplesign.exe" : "simplesign";
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            string bin = Path.Combine(dir.FullName, "src", "Apps", "SimpleSign.Cli", "bin");
            if (Directory.Exists(bin))
            {
                return Directory.EnumerateFiles(bin, exe, SearchOption.AllDirectories)
                    .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}publish{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
                    .Select(f => new FileInfo(f))
                    .OrderByDescending(f => f.LastWriteTimeUtc)
                    .FirstOrDefault()?.FullName;
            }
        }

        return null;
    }
}

[JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(AppSettings))]
internal sealed partial class SettingsJson : JsonSerializerContext;
