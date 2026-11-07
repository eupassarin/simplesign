namespace SimpleSign.Playbook.Workspaces;

/// <summary>The workspace open in the app (one at a time).</summary>
public sealed class WorkspaceState(AppSettingsStore settings)
{
    private readonly Lock _gate = new();
    private Workspace? _current;

    public Workspace? Current
    {
        get
        {
            lock (_gate)
            {
                return _current;
            }
        }
    }

    /// <summary>The open workspace.</summary>
    /// <exception cref="InvalidOperationException">None is open.</exception>
    public Workspace Require() => Current ?? throw new InvalidOperationException("No workspace is open.");

    /// <summary>Opens a workspace folder and remembers it.</summary>
    public Workspace Open(string directory)
    {
        var workspace = Workspace.Open(directory);
        lock (_gate)
        {
            _current = workspace;
        }

        settings.Remember(workspace.Directory);
        return workspace;
    }

    /// <summary>Creates a workspace (from a sample when given) and opens it.</summary>
    public Workspace Create(string directory, string name, string? sampleFolder)
    {
        var workspace = Workspace.Create(directory, name, sampleFolder);
        lock (_gate)
        {
            _current = workspace;
        }

        settings.Remember(workspace.Directory);
        return workspace;
    }
}
