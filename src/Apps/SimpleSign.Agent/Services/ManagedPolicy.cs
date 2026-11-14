using System.Text.Json;
using System.Text.Json.Serialization;

namespace SimpleSign.Agent.Services;

/// <summary>The shape of <c>policy.json</c>, the file an administrator ships with a locked-down installation.</summary>
internal sealed class ManagedPolicyFile
{
    /// <summary>
    /// The settings the administrator fixes: <c>allowedOrigins</c>, <c>signedRequests</c>, <c>trustFrameworks</c>,
    /// <c>agentPort</c>, <c>pinCacheMinutes</c>. A fixed setting is shown read-only and cannot be saved away.
    /// </summary>
    public List<string>? LockedSettings { get; set; }

    /// <summary>The sites allowed without asking the user.</summary>
    public List<string>? AllowedOrigins { get; set; }

    /// <summary>The sites refused without asking the user.</summary>
    public List<string>? BlockedOrigins { get; set; }

    /// <summary>Whether a sign request must carry a token signed by one of <see cref="SignedRequestKeys"/>.</summary>
    public bool? SignedRequestsRequired { get; set; }

    /// <summary>The public keys that may sign a sign request, in PEM form.</summary>
    public List<string>? SignedRequestKeys { get; set; }

    /// <summary>The trust framework ids that are enabled.</summary>
    public List<string>? EnabledTrustFrameworks { get; set; }

    /// <summary>The port the agent listens on.</summary>
    public int? AgentPort { get; set; }

    /// <summary>How long a token PIN is kept in memory, in minutes.</summary>
    public int? PinCacheMinutes { get; set; }
}

[JsonSerializable(typeof(ManagedPolicyFile))]
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
internal sealed partial class ManagedPolicyJsonContext : JsonSerializerContext;

/// <summary>
/// The settings an administrator fixes for every user of a machine, read once at startup from
/// <c>policy.json</c>: the path in <see cref="PathVariable"/>, else the machine folder
/// (<c>/Library/Application Support/SimpleSign</c>, <c>%ProgramData%\SimpleSign</c>, <c>/etc/simplesign</c>).
/// A value it carries is applied to the settings; a value it also locks cannot be changed in the window and is
/// written back over any change. Without the file nothing changes: the agent stays interactive, which is the default.
/// A file that exists but cannot be read is a refusal, not a fallback — the agent answers nothing until it is fixed,
/// because failing open would quietly undo the lock the administrator relied on.
/// </summary>
internal sealed class ManagedPolicy
{
    /// <summary>Environment variable with the path of the policy file.</summary>
    public const string PathVariable = "SIMPLESIGN_AGENT_POLICY";

    /// <summary>Key of the origin allow-list and block-list.</summary>
    public const string Origins = "allowedOrigins";

    /// <summary>Key of the signed-request mode and its keys.</summary>
    public const string SignedRequests = "signedRequests";

    /// <summary>Key of the enabled trust frameworks.</summary>
    public const string TrustFrameworks = "trustFrameworks";

    /// <summary>Key of the agent port.</summary>
    public const string Port = "agentPort";

    /// <summary>Key of the PIN cache.</summary>
    public const string PinCache = "pinCacheMinutes";

    private readonly ManagedPolicyFile? _file;
    private readonly HashSet<string> _locked;

    private ManagedPolicy(ManagedPolicyFile? file, string? path, string? error)
    {
        _file = file;
        Path = path;
        Error = error;
        _locked = new HashSet<string>(file?.LockedSettings ?? [], StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>No policy file: the agent behaves as it always has.</summary>
    public static ManagedPolicy None { get; } = new(null, null, null);

    /// <summary>The file the policy was read from; null when there is none.</summary>
    public string? Path { get; }

    /// <summary>Why the policy file could not be read; null when it is fine or absent.</summary>
    public string? Error { get; }

    /// <summary>Whether a policy file was found.</summary>
    public bool Exists => _file is not null || Error is not null;

    /// <summary>The settings file an administrator would put the policy in on this system.</summary>
    public static string MachinePath => OperatingSystem.IsWindows()
        ? System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SimpleSign", "policy.json")
        : OperatingSystem.IsMacOS()
            ? "/Library/Application Support/SimpleSign/policy.json"
            : "/etc/simplesign/policy.json";

    /// <summary>Reads the policy from <see cref="PathVariable"/> or <see cref="MachinePath"/>; never throws.</summary>
    public static ManagedPolicy Load() =>
        Load(Environment.GetEnvironmentVariable(PathVariable) is { Length: > 0 } fromEnvironment ? fromEnvironment : MachinePath);

    /// <summary>Reads the policy from one file; never throws.</summary>
    /// <param name="path">The policy file.</param>
    public static ManagedPolicy Load(string path)
    {
        if (!File.Exists(path))
        {
            return None;
        }

        try
        {
            var file = JsonSerializer.Deserialize(File.ReadAllText(path), ManagedPolicyJsonContext.Default.ManagedPolicyFile);
            return file is null
                ? new ManagedPolicy(null, path, "policy.json is empty.")
                : new ManagedPolicy(file, path, null);
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return new ManagedPolicy(null, path, ex.Message);
        }
    }

    /// <summary>Whether the administrator fixed <paramref name="key"/>.</summary>
    /// <param name="key">One of this class's key constants.</param>
    public bool IsLocked(string key) => _locked.Contains(key);

    /// <summary>Puts the policy's values into <paramref name="settings"/>.</summary>
    /// <param name="settings">The settings to adjust.</param>
    /// <param name="lockedOnly">True to re-apply only the locked values (before saving).</param>
    public void ApplyTo(AppSettings settings, bool lockedOnly)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (_file is not { } file)
        {
            return;
        }

        if (Wanted(Origins, lockedOnly))
        {
            if (file.AllowedOrigins is { } allowed)
            {
                settings.AllowedOrigins = [.. allowed];
            }

            if (file.BlockedOrigins is { } blocked)
            {
                settings.BlockedOrigins = [.. blocked];
            }
        }

        if (Wanted(SignedRequests, lockedOnly))
        {
            if (file.SignedRequestsRequired is { } required)
            {
                settings.SignedRequestsRequired = required;
            }

            if (file.SignedRequestKeys is { } keys)
            {
                settings.SignedRequestKeys = [.. keys];
            }
        }

        if (Wanted(TrustFrameworks, lockedOnly) && file.EnabledTrustFrameworks is { } frameworks)
        {
            settings.EnabledTrustFrameworks = [.. frameworks];
        }

        if (Wanted(Port, lockedOnly) && file.AgentPort is { } port)
        {
            settings.AgentPort = port;
        }

        if (Wanted(PinCache, lockedOnly) && file.PinCacheMinutes is { } minutes)
        {
            settings.PinCacheMinutes = minutes;
        }
    }

    private bool Wanted(string key, bool lockedOnly) => !lockedOnly || IsLocked(key);
}
