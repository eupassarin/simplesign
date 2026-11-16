using System.Collections.Concurrent;
using System.Text.Json;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Interop.Tests;

/// <summary>An independent implementation the tests compare SimpleSign with.</summary>
public enum InteropTool
{
    /// <summary>qpdf: PDF syntax and cross-reference structure (<c>qpdf --check</c>).</summary>
    Qpdf,

    /// <summary>OpenSSL 3: CMS (<c>openssl cms -verify</c>, <c>openssl cms -sign -cades</c>).</summary>
    OpenSsl,

    /// <summary>xmlsec1: XML-DSig (<c>xmlsec1 --verify</c>).</summary>
    Xmlsec1,

    /// <summary>pyHanko, through <c>tools/pyhanko_tool.py</c>: PAdES validation and signing.</summary>
    PyHanko,
}

/// <summary>
/// Finds and runs the <see cref="InteropTool"/>s. Each is taken from the PATH (<c>qpdf</c>, <c>openssl</c>,
/// <c>xmlsec1</c>, <c>python3</c> with pyHanko installed), or from <c>SIMPLESIGN_QPDF</c>, <c>SIMPLESIGN_OPENSSL</c>,
/// <c>SIMPLESIGN_XMLSEC1</c>, <c>SIMPLESIGN_PYTHON</c>. Without it the calling test is skipped, or fails when
/// <c>SIMPLESIGN_REQUIRE_INTEROP</c> is "true" (the CI job installs them all, so a missing tool is an error there).
/// </summary>
public static class InteropTools
{
    private static readonly ConcurrentDictionary<InteropTool, Lazy<string?>> Problems = new();

    private static string PyHankoScript => Path.Combine(AppContext.BaseDirectory, "tools", "pyhanko_tool.py");

    /// <summary>
    /// Where the files a tool rejected are written: <c>SIMPLESIGN_INTEROP_FAILURES</c>, or <c>interop-failures</c>
    /// next to the test assembly.
    /// </summary>
    public static string FailuresDirectory =>
        Environment.GetEnvironmentVariable("SIMPLESIGN_INTEROP_FAILURES") is { Length: > 0 } path
            ? path
            : Path.Combine(AppContext.BaseDirectory, "interop-failures");

    /// <summary>Skips the calling test when <paramref name="tool"/> is missing; fails it instead when <c>SIMPLESIGN_REQUIRE_INTEROP</c> is "true".</summary>
    public static void Require(InteropTool tool)
    {
        if (Problems.GetOrAdd(tool, t => new Lazy<string?>(() => FindProblem(t))).Value is not { } problem)
        {
            return;
        }

        if (string.Equals(Environment.GetEnvironmentVariable("SIMPLESIGN_REQUIRE_INTEROP"), "true", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(problem);
        }

        Skip.If(true, problem);
    }

    /// <summary>Runs <paramref name="tool"/> (for pyHanko, a subcommand of <c>tools/pyhanko_tool.py</c>).</summary>
    public static Task<ExternalProcessResult> RunAsync(InteropTool tool, params string[] args) =>
        tool == InteropTool.PyHanko
            ? ExternalProcess.RunAsync(Executable(tool), ["-I", PyHankoScript, .. args])
            : ExternalProcess.RunAsync(Executable(tool), args);

    /// <summary>pyHanko's verdict on every signature and document timestamp of <paramref name="pdf"/>, trusting only <paramref name="roots"/>.</summary>
    public static async Task<IReadOnlyList<PyHankoSignature>> PyHankoValidateAsync(string pdf, params string[] roots)
    {
        var run = await RunAsync(InteropTool.PyHanko, ["validate", pdf, .. roots]);
        if (run.ExitCode != 0)
        {
            throw new InvalidOperationException($"pyHanko could not read {pdf} ({run.Output}).");
        }

        return JsonSerializer.Deserialize<PyHankoReport>(run.Stdout, JsonOptions)?.Signatures
            ?? throw new InvalidOperationException($"pyHanko printed no report ({run.Output}).");
    }

    /// <summary>Keeps a file a tool rejected in <see cref="FailuresDirectory"/>, for the CI artifact.</summary>
    /// <returns>Where it was written.</returns>
    public static string SaveRejected(string name, byte[] content)
    {
        Directory.CreateDirectory(FailuresDirectory);
        string path = Path.Combine(FailuresDirectory, name);
        File.WriteAllBytes(path, content);
        return path;
    }

    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower };

    private static string Executable(InteropTool tool)
    {
        var (variable, fallback) = tool switch
        {
            InteropTool.Qpdf => ("SIMPLESIGN_QPDF", "qpdf"),
            InteropTool.OpenSsl => ("SIMPLESIGN_OPENSSL", "openssl"),
            InteropTool.Xmlsec1 => ("SIMPLESIGN_XMLSEC1", "xmlsec1"),
            _ => ("SIMPLESIGN_PYTHON", "python3"),
        };
        return Environment.GetEnvironmentVariable(variable) is { Length: > 0 } path ? path : fallback;
    }

    private static string? FindProblem(InteropTool tool)
    {
        string executable = Executable(tool);
        ExternalProcessResult? probe;
        try
        {
            probe = tool switch
            {
                InteropTool.Qpdf => ExternalProcess.RunAsync(executable, ["--version"], TimeSpan.FromSeconds(30)).GetAwaiter().GetResult(),
                InteropTool.OpenSsl => ExternalProcess.RunAsync(executable, ["version"], TimeSpan.FromSeconds(30)).GetAwaiter().GetResult(),
                InteropTool.Xmlsec1 => ExternalProcess.RunAsync(executable, ["--version"], TimeSpan.FromSeconds(30)).GetAwaiter().GetResult(),
                _ => ExternalProcess.RunAsync(executable, ["-I", "-c", "import pyhanko.sign, pyhanko_certvalidator"], TimeSpan.FromSeconds(30)).GetAwaiter().GetResult(),
            };
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or TimeoutException or InvalidOperationException)
        {
            probe = null;
        }

        string install = "Install it (CI: apt-get install qpdf xmlsec1; pip install -r tests/integration/SimpleSign.Interop.Tests/tools/requirements.txt) or set its SIMPLESIGN_* variable.";
        if (probe is not { ExitCode: 0 })
        {
            return $"{tool} is not available ({executable}). {install}";
        }

        // LibreSSL (macOS's /usr/bin/openssl) has no `cms -cades`.
        return tool == InteropTool.OpenSsl && !probe.Stdout.StartsWith("OpenSSL ", StringComparison.Ordinal)
            ? $"{executable} is {probe.Stdout.Trim()}, not OpenSSL 3. {install}"
            : null;
    }
}

/// <summary>What <c>tools/pyhanko_tool.py validate</c> prints.</summary>
public sealed record PyHankoReport(IReadOnlyList<PyHankoSignature> Signatures);

/// <summary>pyHanko's verdict on one signature or document timestamp (see <c>tools/pyhanko_tool.py</c>).</summary>
public sealed record PyHankoSignature(
    string? Field,
    string? Kind,
    bool Intact,
    bool Valid,
    bool Trusted,
    string? Coverage,
    string? ModificationLevel,
    bool? DocmdpOk,
    bool? TimestampTrusted,
    string? Summary,
    string? Error);
