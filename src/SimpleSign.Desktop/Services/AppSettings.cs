using System.Text.Json;
using System.Text.Json.Serialization;

namespace SimpleSign.Desktop.Services;

/// <summary>User settings, stored as JSON in the user's application-data folder.</summary>
internal sealed class AppSettings
{
    /// <summary>Default TSA / ICP-Brasil ACT URL.</summary>
    public string TsaUrl { get; set; } = "http://timestamp.digicert.com";

    /// <summary>LCR cache folder; empty = memory only.</summary>
    public string CrlCacheDirectory { get; set; } = "";

    /// <summary>Trust the ICP-Brasil homologation hierarchy too.</summary>
    public bool IcpHomologation { get; set; }

    /// <summary>Run the local signing agent.</summary>
    public bool AgentEnabled { get; set; } = true;

    /// <summary>Agent port on 127.0.0.1.</summary>
    public int AgentPort { get; set; } = 21590;

    /// <summary>Origins the user allowed permanently (exact scheme://host[:port]).</summary>
    public List<string> AllowedOrigins { get; set; } = [];

    /// <summary>Origins the user blocked permanently.</summary>
    public List<string> BlockedOrigins { get; set; } = [];

    /// <summary>Minutes a token PIN is kept in memory after use; 0 = ask every time.</summary>
    public int PinCacheMinutes { get; set; }

    /// <summary>"System", "Light" or "Dark".</summary>
    public string Theme { get; set; } = "System";
}

[JsonSerializable(typeof(AppSettings))]
[JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
internal sealed partial class AppSettingsJsonContext : JsonSerializerContext;

/// <summary>Loads and saves <see cref="AppSettings"/>.</summary>
internal sealed class SettingsStore
{
    private readonly string _path;
    private readonly Lock _gate = new();

    public SettingsStore(string? directory = null)
    {
        string folder = directory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData, Environment.SpecialFolderOption.Create), "SimpleSign");
        Directory.CreateDirectory(folder);
        _path = Path.Combine(folder, "settings.json");
        Current = Load();
    }

    public AppSettings Current { get; }

    public event EventHandler? Changed;

    public void Save()
    {
        lock (_gate)
        {
            string json = JsonSerializer.Serialize(Current, AppSettingsJsonContext.Default.AppSettings);
            File.WriteAllText(_path + ".tmp", json);
            File.Move(_path + ".tmp", _path, overwrite: true);
        }

        Changed?.Invoke(this, EventArgs.Empty);
    }

    private AppSettings Load()
    {
        try
        {
            return File.Exists(_path)
                ? JsonSerializer.Deserialize(File.ReadAllText(_path), AppSettingsJsonContext.Default.AppSettings) ?? new AppSettings()
                : new AppSettings();
        }
        catch (JsonException)
        {
            return new AppSettings();
        }
    }
}
