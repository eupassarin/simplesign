using System.Text.Json;
using System.Text.Json.Serialization;

namespace SimpleSign.Agent.Services;

/// <summary>Agent settings, stored as JSON in the user's application-data folder.</summary>
internal sealed class AppSettings
{
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

    /// <summary>
    /// The ids of the trust frameworks the user enabled (<c>icp-brasil</c>, <c>govbr</c>, <c>iofe</c>, <c>eidas</c>):
    /// only these answer <c>?country=</c>, <c>?trust=</c> and <c>filterIcpBrasil</c>, and only these put a badge on a
    /// certificate in the window. Null means the key is absent, which <see cref="SettingsStore"/> turns into the
    /// frameworks an older agent filtered by; a new installation starts with none.
    /// </summary>
    public List<string>? EnabledTrustFrameworks { get; set; }

    /// <summary>
    /// Whether <c>POST /api/sign</c> is answered only for a request a configured key signed
    /// (<see cref="Server.SignedRequestVerifier"/>). Off by default: any allowed site may ask, as before.
    /// </summary>
    public bool SignedRequestsRequired { get; set; }

    /// <summary>
    /// The public keys whose signature makes a sign request acceptable, in PEM form
    /// (<c>-----BEGIN PUBLIC KEY-----</c>, an EC or RSA SubjectPublicKeyInfo).
    /// </summary>
    public List<string>? SignedRequestKeys { get; set; }

    /// <summary>"en-US", "pt-BR" or "es-ES"; null follows the operating system.</summary>
    public string? Language { get; set; }

    /// <summary>"system", "light" or "dark".</summary>
    public string Theme { get; set; } = "system";

    /// <summary>False until the window was shown once (it opens by itself on the first run).</summary>
    public bool FirstRunDone { get; set; }
}

[JsonSerializable(typeof(AppSettings))]
[JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
internal sealed partial class AppSettingsJsonContext : JsonSerializerContext;

/// <summary>Loads and saves <see cref="AppSettings"/>.</summary>
internal sealed class SettingsStore
{
    private readonly string _path;
    private readonly Lock _gate = new();

    /// <summary>Loads the settings, with the values an administrator's policy file fixes applied on top.</summary>
    /// <param name="directory">Where settings.json lives; null uses the user's application-data folder.</param>
    /// <param name="policy">The administrator's policy; null reads it from its usual places.</param>
    public SettingsStore(string? directory = null, ManagedPolicy? policy = null)
    {
        string folder = directory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData, Environment.SpecialFolderOption.Create), "SimpleSign");
        Directory.CreateDirectory(folder);
        _path = Path.Combine(folder, "settings.json");
        Policy = policy ?? ManagedPolicy.Load();
        bool existed = File.Exists(_path);
        Current = Load();
        // An agent that was already running filtered by ICP-Brasil and Gov.br, so an upgrade keeps them: the ids are
        // written only when the file is there without the key. A new installation enables nothing until the user does.
        Current.EnabledTrustFrameworks ??= existed ? [.. TrustFrameworkCatalog.LegacyDefaults] : [];
        Policy.ApplyTo(Current, lockedOnly: false);
    }

    /// <summary>The administrator's policy file, which may fix some settings. Never null.</summary>
    public ManagedPolicy Policy { get; }

    /// <summary>Whether an administrator fixed <paramref name="key"/>, so the window shows it read-only.</summary>
    /// <param name="key">One of the <see cref="ManagedPolicy"/> keys.</param>
    public bool IsLocked(string key) => Policy.IsLocked(key);

    /// <summary>The folder that holds settings.json.</summary>
    public string Folder => Path.GetDirectoryName(_path)!;

    public AppSettings Current { get; }

    public event EventHandler? Changed;

    public void Save()
    {
        lock (_gate)
        {
            // A locked value can never be written away, whatever changed it.
            Policy.ApplyTo(Current, lockedOnly: true);
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
