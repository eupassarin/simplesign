using System.Security.Cryptography;
using System.Text;
using Shouldly;
using SimpleSign.TestHelpers;

namespace SimpleSign.PAdES.Tests.Pdf.Parity;

/// <summary>
/// Golden snapshots of what the PDF object model reads and writes (ADR 0032), in <c>Snapshots/</c> next to this file.
/// They were taken when the model's output had been checked against the code it replaced (byte for byte, or with each
/// difference explained); a change now fails until it is looked at and the snapshots are written again, with
/// <c>SIMPLESIGN_UPDATE_SNAPSHOTS=1</c>.
/// </summary>
internal static class Snapshot
{
#pragma warning disable IDE0330 // System.Threading.Lock is not in net8.0
    private static readonly object s_lock = new();
#pragma warning restore IDE0330
    private static readonly Dictionary<string, SortedDictionary<string, string>> s_keyed = new(StringComparer.Ordinal);

    /// <summary>Whether the snapshots are being written rather than checked.</summary>
    public static bool Updating => Environment.GetEnvironmentVariable("SIMPLESIGN_UPDATE_SNAPSHOTS") == "1";

    /// <summary>
    /// The framework suffix of a snapshot that depends on it: zlib compresses differently from .NET 9 on (zlib-ng),
    /// so the bytes of an update with compressed streams differ between net8.0 and net10.0.
    /// </summary>
    public static string Framework => $"net{Environment.Version.Major}";

    /// <summary>
    /// Whether bytes compressed at run time are those the per-framework snapshots hold: zlib-ng on every system from
    /// .NET 9; on .NET 8, the system zlib of Linux and macOS, not the zlib .NET 8 bundles for Windows, whose bytes differ.
    /// </summary>
    public static bool CompressionMatches => Environment.Version.Major >= 9 || !OperatingSystem.IsWindows();

    /// <summary>
    /// Checks (or writes) an entry of a per-framework keyed snapshot (<c>{file}.{Framework}.txt</c>): bytes compressed at
    /// run time. Not checked where <see cref="CompressionMatches"/> is false.
    /// </summary>
    /// <param name="file">Its path under <c>Snapshots/</c>, without the framework and extension.</param>
    /// <param name="key">The entry's key.</param>
    /// <param name="bytes">The bytes whose SHA-256 it holds.</param>
    public static void MatchCompressed(string file, string key, ReadOnlySpan<byte> bytes)
    {
        if (CompressionMatches)
        {
            MatchKey($"{file}.{Framework}.txt", key, Hash(bytes));
        }
    }

    /// <summary>The SHA-256 of some bytes, in hexadecimal.</summary>
    public static string Hash(ReadOnlySpan<byte> bytes) => Convert.ToHexString(SHA256.HashData(bytes));

    /// <summary>Checks (or writes) a whole-file snapshot.</summary>
    /// <param name="name">Its path under <c>Snapshots/</c>.</param>
    /// <param name="actual">What it must hold.</param>
    /// <param name="compressed">Whether it holds facts of bytes compressed at run time (not checked where <see cref="CompressionMatches"/> is false).</param>
    public static void MatchFile(string name, string actual, bool compressed = false)
    {
        if (compressed && !CompressionMatches)
        {
            return;
        }

        string path = Path.Combine(Folder(), name);
        if (Updating)
        {
            lock (s_lock)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                File.WriteAllText(path, actual);
            }

            return;
        }

        File.Exists(path).ShouldBeTrue($"There is no snapshot {name}: write it with SIMPLESIGN_UPDATE_SNAPSHOTS=1.");
        string expected = File.ReadAllText(path).Replace("\r\n", "\n", StringComparison.Ordinal);
        if (expected != actual)
        {
            string[] want = expected.Split('\n'), got = actual.Split('\n');
            int line = 0;
            while (line < want.Length && line < got.Length && want[line] == got[line])
            {
                line++;
            }

            actual.ShouldBe(expected, $"{name} differs from line {line + 1}: expected '{(line < want.Length ? want[line] : "<end>")}', got '{(line < got.Length ? got[line] : "<end>")}'.");
        }
    }

    /// <summary>Checks (or writes) one entry of a keyed snapshot: one line per key, <c>key</c>, a tab, <c>value</c>.</summary>
    /// <param name="file">Its path under <c>Snapshots/</c>.</param>
    /// <param name="key">The entry's key (no tab, no line end).</param>
    /// <param name="value">What it must hold (no line end).</param>
    public static void MatchKey(string file, string key, string value)
    {
        string path = Path.Combine(Folder(), file);
        lock (s_lock)
        {
            if (!s_keyed.TryGetValue(path, out var entries))
            {
                entries = new SortedDictionary<string, string>(StringComparer.Ordinal);
                if (File.Exists(path))
                {
                    foreach (string line in File.ReadAllLines(path))
                    {
                        int tab = line.IndexOf('\t', StringComparison.Ordinal);
                        if (tab > 0)
                        {
                            entries[line[..tab]] = line[(tab + 1)..];
                        }
                    }
                }

                s_keyed[path] = entries;
            }

            if (Updating)
            {
                entries[key] = value;
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                File.WriteAllLines(path, entries.Select(e => $"{e.Key}\t{e.Value}"));
                return;
            }

            entries.TryGetValue(key, out string? expected).ShouldBeTrue($"{file} has no entry {key}: write it with SIMPLESIGN_UPDATE_SNAPSHOTS=1.");
            value.ShouldBe(expected, $"{file}, {key}");
        }
    }

    /// <summary>A text as one line: backslashes, CR and LF escaped.</summary>
    public static string OneLine(string text) =>
        new StringBuilder(text).Replace("\\", "\\\\").Replace("\r", "\\r").Replace("\n", "\\n").Replace("\t", "\\t").ToString();

    /// <summary>
    /// The snapshots' folder, found from the repository root (as the fixtures are): a CI build is deterministic and maps
    /// the source paths, so the compile-time path of this file is not one on disk there.
    /// </summary>
    private static string Folder() =>
        RepositoryPaths.Get("tests", "unit", "Formats", "SimpleSign.PAdES.Tests", "Pdf", "Parity", "Snapshots");
}
