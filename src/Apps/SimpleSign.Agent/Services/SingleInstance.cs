using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;

namespace SimpleSign.Agent.Services;

/// <summary>
/// One agent per user: a second launch asks the running one to show its window (over a
/// current-user-only named pipe) and exits, instead of failing on a port that is already in use.
/// </summary>
internal sealed class SingleInstance : IDisposable
{
    private readonly string _name;
    private readonly CancellationTokenSource _stop = new();

    private SingleInstance(string name)
    {
        _name = name;
    }

    /// <summary>Another launch asked for the window. Raised on a thread-pool thread.</summary>
    public event EventHandler? ShowRequested;

    /// <summary>The pipe name for the current user.</summary>
    public static string DefaultName =>
        "simplesign-agent-" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Environment.UserName)))[..12].ToLowerInvariant();

    /// <summary>Null when another instance is running (it was asked to show its window).</summary>
    public static SingleInstance? Acquire(string? name = null)
    {
        name ??= DefaultName;
        if (Signal(name))
        {
            return null;
        }

        var instance = new SingleInstance(name);
        _ = Task.Run(instance.ListenAsync);
        return instance;
    }

    public void Dispose()
    {
        _stop.Cancel();
        _stop.Dispose();
        // Leave no socket file behind, so the next start does not wait on a dead one.
        if (UnixSocketPath(_name) is { } path)
        {
            TryDelete(path);
        }
    }

    private static string? UnixSocketPath(string name) =>
        OperatingSystem.IsWindows() ? null : Path.Combine(Path.GetTempPath(), "CoreFxPipe_" + name);

    private static bool Signal(string name)
    {
        // On Unix the pipe is a socket file: when it is not there, nobody is listening (no wait).
        if (UnixSocketPath(name) is { } path && !File.Exists(path))
        {
            return false;
        }

        try
        {
            using var client = new NamedPipeClientStream(".", name, PipeDirection.Out, PipeOptions.CurrentUserOnly);
            client.Connect(150);
            client.WriteByte(1);
            client.Flush();
            return true;
        }
        catch (Exception ex) when (ex is TimeoutException or IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private async Task ListenAsync()
    {
        var token = _stop.Token;
        bool cleaned = false;
        while (!token.IsCancellationRequested)
        {
            try
            {
                var server = new NamedPipeServerStream(_name, PipeDirection.In, 1, PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                await using (server)
                {
                    await server.WaitForConnectionAsync(token);
                    byte[] buffer = new byte[1];
                    if (await server.ReadAsync(buffer, token) == 1)
                    {
                        ShowRequested?.Invoke(this, EventArgs.Empty);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // A socket file left by a crashed agent: nobody answered Signal, so it is stale.
                if (!cleaned && UnixSocketPath(_name) is { } path)
                {
                    cleaned = true;
                    TryDelete(path);
                    continue;
                }

                return;
            }
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Without the pipe the agent still works; only "show the running window" is lost.
        }
    }
}
