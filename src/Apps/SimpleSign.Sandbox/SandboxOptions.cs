namespace SimpleSign.Sandbox;

/// <summary>How a Sandbox instance runs: its environment (name, folder, public URL) and where it listens.</summary>
public sealed record SandboxOptions
{
    /// <summary>The default port (HTTP services, admin API and UI).</summary>
    public const int DefaultPort = 5300;

    /// <summary>The environment's name: each name has its own folder, PKI and state.</summary>
    public string Name { get; init; } = "default";

    /// <summary>The port to listen on.</summary>
    public int Port { get; init; } = DefaultPort;

    /// <summary>
    /// The URL clients use to reach this Sandbox. It is written into the certificates (CRL
    /// distribution points, AIA), so it is fixed when the environment is created. Null: http://localhost:{port}.
    /// </summary>
    public Uri? PublicBaseUrl { get; init; }

    /// <summary>Where the environment is kept. Null: the user's local application data.</summary>
    public string? DataDirectory { get; init; }

    /// <summary>A new environment in a temporary folder, deleted when the Sandbox stops.</summary>
    public bool Ephemeral { get; init; }

    /// <summary>Listen on every interface (a lab network) instead of localhost only.</summary>
    public bool ListenAnyAddress { get; init; }

    /// <summary>Let the admin API (issue, revoke, faults) answer requests from other machines.</summary>
    public bool AllowRemoteAdmin { get; init; }

    /// <summary>Open the UI in the browser once started.</summary>
    public bool OpenBrowser { get; init; } = true;

    /// <summary>The URL written into new certificates.</summary>
    public Uri BaseUrl => PublicBaseUrl ?? new Uri($"http://localhost:{Port}/");

    /// <summary>The environment's folder.</summary>
    public string ResolveDataDirectory() => DataDirectory
        ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SimpleSign", "Sandbox", Name);

    /// <summary>Reads the command line.</summary>
    /// <remarks>
    /// --port N, --name NAME, --public-base-url URL, --data-dir DIR, --ephemeral, --listen-any,
    /// --allow-remote-admin, --no-browser.
    /// </remarks>
    public static SandboxOptions Parse(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);
        var options = new SandboxOptions();
        for (int i = 0; i < args.Count; i++)
        {
            string? next = i + 1 < args.Count ? args[i + 1] : null;
            switch (args[i])
            {
                case "--port" when int.TryParse(next, out int port):
                    options = options with { Port = port };
                    i++;
                    break;
                case "--name" when next is not null:
                    options = options with { Name = next };
                    i++;
                    break;
                case "--public-base-url" when Uri.TryCreate(next, UriKind.Absolute, out var url):
                    options = options with { PublicBaseUrl = url.AbsoluteUri.EndsWith('/') ? url : new Uri(url.AbsoluteUri + "/") };
                    i++;
                    break;
                case "--data-dir" when next is not null:
                    options = options with { DataDirectory = Path.GetFullPath(next) };
                    i++;
                    break;
                case "--ephemeral":
                    options = options with { Ephemeral = true };
                    break;
                case "--listen-any":
                    options = options with { ListenAnyAddress = true };
                    break;
                case "--allow-remote-admin":
                    options = options with { AllowRemoteAdmin = true };
                    break;
                case "--no-browser":
                    options = options with { OpenBrowser = false };
                    break;
                default:
                    break;
            }
        }

        return options;
    }
}
