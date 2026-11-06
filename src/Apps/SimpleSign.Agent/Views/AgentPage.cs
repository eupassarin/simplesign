using Avalonia.Controls;
using SimpleSign.Agent.Services;

namespace SimpleSign.Agent.Views;

/// <summary>
/// A section of the window. Its content is rebuilt from its state whenever something changes
/// (the agent, the language), so there is no binding to keep in step.
/// </summary>
internal abstract class AgentPage : UserControl
{
    protected AgentPage(MainWindow host)
    {
        Host = host;
    }

    protected MainWindow Host { get; }

    protected AgentController Controller => Host.Controller;

    public void Rebuild() => Content = Build();

    /// <summary>The agent started, stopped, or its settings or certificates changed.</summary>
    public virtual void OnAgentChanged() => Rebuild();

    /// <summary>The activity log got an entry (null: it was cleared).</summary>
    public virtual void OnActivity(LogEntry? entry)
    {
    }

    protected abstract Control Build();
}
