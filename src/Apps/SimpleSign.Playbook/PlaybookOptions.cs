namespace SimpleSign.Playbook;

/// <summary>How the Playbook app runs.</summary>
public sealed record PlaybookOptions
{
    public const int DefaultPort = 5400;

    public int Port { get; init; } = DefaultPort;

    /// <summary>A workspace to open at start.</summary>
    public string? Workspace { get; init; }

    public bool OpenBrowser { get; init; } = true;

    /// <summary>Where this machine's settings are kept. Null: %LocalAppData%/SimpleSign/Playbook.</summary>
    public string? SettingsDirectory { get; init; }

    /// <summary>Reads --port N, --workspace DIR, --no-browser.</summary>
    /// <exception cref="ArgumentException">An option has no value or a bad one.</exception>
    public static PlaybookOptions Parse(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);
        var options = new PlaybookOptions();
        for (int i = 0; i < args.Count; i++)
        {
            string? next = i + 1 < args.Count ? args[i + 1] : null;
            switch (args[i])
            {
                case "--port" when int.TryParse(next, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int port) && port is > 0 and < 65536:
                    options = options with { Port = port };
                    i++;
                    break;
                case "--workspace" when next is not null:
                    options = options with { Workspace = next };
                    i++;
                    break;
                case "--no-browser":
                    options = options with { OpenBrowser = false };
                    break;
                case "--port" or "--workspace":
                    throw new ArgumentException($"{args[i]} needs a value.");
                default:
                    break;
            }
        }

        return options;
    }
}
