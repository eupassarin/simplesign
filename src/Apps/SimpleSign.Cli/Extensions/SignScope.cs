using SimpleSign.Cli.Extensibility;

namespace SimpleSign.Cli.Extensions;

/// <summary>
/// The request of an extension's command that is running the standard <c>sign</c> (<see cref="CliExtensionContext.SignAsync"/>):
/// <c>sign</c> reads from it what the extension adds to the signature. It follows the asynchronous flow of the run,
/// so two runs do not see each other's.
/// </summary>
internal static class SignScope
{
    private static readonly AsyncLocal<CliSignRequest?> s_current = new();

    /// <summary>The request <c>sign</c> is running for; null when the user ran <c>sign</c> itself.</summary>
    internal static CliSignRequest? Current => s_current.Value;

    /// <summary>Makes <paramref name="request"/> the current one until the result is disposed.</summary>
    internal static IDisposable Enter(CliSignRequest request)
    {
        var previous = s_current.Value;
        s_current.Value = request;
        return new Scope(previous);
    }

    private sealed class Scope(CliSignRequest? previous) : IDisposable
    {
        public void Dispose() => s_current.Value = previous;
    }
}
