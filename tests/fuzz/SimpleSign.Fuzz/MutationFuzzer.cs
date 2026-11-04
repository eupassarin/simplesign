using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace SimpleSign.Fuzz;

/// <summary>
/// Self-contained mutation fuzzer, used when no AFL/libFuzzer front-end is installed (CI).
/// It mutates the seed corpus of a target, runs each input in-process, and records two kinds
/// of finding: an exception the target does not expect from malformed input (crash), and an
/// input that runs longer than the hang limit (hang). Findings are written to the output
/// directory as <c>crash-*.bin</c> / <c>hang-*.bin</c> with a <c>.txt</c> report next to each.
/// </summary>
internal sealed class MutationFuzzer
{
    private static readonly byte[][] Tokens =
    [
        "<<"u8.ToArray(), ">>"u8.ToArray(), "["u8.ToArray(), "]"u8.ToArray(), "("u8.ToArray(), ")"u8.ToArray(),
        " obj "u8.ToArray(), "endobj"u8.ToArray(), "stream\n"u8.ToArray(), "\nendstream"u8.ToArray(),
        "xref\n0 1\n"u8.ToArray(), "trailer"u8.ToArray(), "startxref\n"u8.ToArray(), "%%EOF"u8.ToArray(),
        "/Length 2147483647"u8.ToArray(), "/Length -1"u8.ToArray(), "/Size 99999999"u8.ToArray(),
        "/Prev 0"u8.ToArray(), "/ByteRange [0 -1 9999999999 5]"u8.ToArray(), "/Contents <"u8.ToArray(),
        "/Type /Sig"u8.ToArray(), "/FT /Sig"u8.ToArray(), "/DSS"u8.ToArray(), "/ObjStm"u8.ToArray(),
        "1 0 R"u8.ToArray(), "99999999 0 R"u8.ToArray(), "<div>"u8.ToArray(), "</div>"u8.ToArray(),
        "<table><tr><td>"u8.ToArray(), "<svg><use href='#a'/>"u8.ToArray(), "calc(1px*(2+"u8.ToArray(),
        "@media print{"u8.ToArray(), ":not("u8.ToArray(), "}"u8.ToArray(), "{"u8.ToArray(),
        [0x30, 0x84, 0x7F, 0xFF, 0xFF, 0xFF], [0x30, 0x80], [0x02, 0x81, 0x00], [0x06, 0x00], [0xA0, 0x83, 0xFF, 0xFF, 0xFF],
    ];

    private readonly string _name;
    private readonly Action<byte[]> _target;
    private readonly Func<Exception, bool> _isExpected;
    private readonly List<byte[]> _corpus;
    private readonly Random _random;
    private readonly string _outputDirectory;
    private readonly TimeSpan _hangLimit;
    private readonly HashSet<string> _seenSignatures = [];

    public MutationFuzzer(string name, Action<byte[]> target, Func<Exception, bool> isExpected, IEnumerable<byte[]> seeds, int seed, string outputDirectory, TimeSpan hangLimit)
    {
        _name = name;
        _target = target;
        _isExpected = isExpected;
        _corpus = [.. seeds.Where(s => s.Length > 0)];
        if (_corpus.Count == 0)
        {
            _corpus.Add("%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"u8.ToArray());
        }

        _random = new Random(seed);
        _outputDirectory = outputDirectory;
        _hangLimit = hangLimit;
    }

    /// <summary>Number of distinct findings recorded so far.</summary>
    public int Findings { get; private set; }

    /// <summary>Number of inputs executed.</summary>
    public long Executions { get; private set; }

    /// <summary>Runs mutated inputs until the time budget is spent or a hang stops the run.</summary>
    public void Run(TimeSpan budget)
    {
        var clock = Stopwatch.StartNew();

        // Seeds first, unmutated.
        foreach (byte[] seed in _corpus.ToArray())
        {
            if (!Execute(seed))
            {
                return;
            }
        }

        while (clock.Elapsed < budget)
        {
            byte[] input = Mutate(_corpus[_random.Next(_corpus.Count)]);
            if (!Execute(input))
            {
                return;
            }
        }
    }

    /// <summary>Runs one input; returns false when it hung (the worker thread cannot be reclaimed).</summary>
    private bool Execute(byte[] input)
    {
        Executions++;
        Exception? failure = null;
        var worker = Task.Factory.StartNew(
            () =>
            {
                try
                {
                    _target(input);
                }
                catch (Exception ex) when (!_isExpected(ex))
                {
                    failure = ex;
                }
                catch (Exception)
                {
                    // Expected for malformed input.
                }
            },
            CancellationToken.None,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default);

        if (!worker.Wait(_hangLimit))
        {
            Record("hang", input, $"Input ran longer than {_hangLimit.TotalSeconds:0} s.", "hang");
            return false;
        }

        if (failure is not null)
        {
            string top = failure.StackTrace?.Split('\n').FirstOrDefault(l => l.Contains("SimpleSign.", StringComparison.Ordinal))?.Trim() ?? "?";
            Record("crash", input, failure.ToString(), $"{failure.GetType().FullName}|{top}");

            // Keep crashing inputs out of the corpus; keep small interesting ones for further mutation.
        }
        else if (input.Length < 1_000_000 && _corpus.Count < 512 && _random.Next(64) == 0)
        {
            _corpus.Add(input);
        }

        return true;
    }

    private void Record(string kind, byte[] input, string report, string signature)
    {
        if (!_seenSignatures.Add(signature))
        {
            return;
        }

        Findings++;
        Directory.CreateDirectory(_outputDirectory);
        string hash = Convert.ToHexString(SHA256.HashData(input))[..16].ToLowerInvariant();
        string path = Path.Combine(_outputDirectory, $"{kind}-{_name}-{hash}");
        File.WriteAllBytes(path + ".bin", input);
        File.WriteAllText(path + ".txt", $"target: {_name}\nkind: {kind}\nsignature: {signature}\n\n{report}\n");
        Console.WriteLine($"[{_name}] {kind.ToUpperInvariant()} #{Findings}: {signature}");
        Console.WriteLine($"         saved {path}.bin");
    }

    private byte[] Mutate(byte[] source)
    {
        var data = new List<byte>(source);
        int count = 1 + _random.Next(4);
        for (int i = 0; i < count; i++)
        {
            ApplyOne(data);
        }

        return [.. data];
    }

    private void ApplyOne(List<byte> data)
    {
        int Pos(int extra = 0) => data.Count == 0 ? 0 : _random.Next(data.Count + extra);

        switch (_random.Next(10))
        {
            case 0 when data.Count > 0: // bit flip
                {
                    int p = Pos();
                    data[p] ^= (byte)(1 << _random.Next(8));
                    break;
                }

            case 1 when data.Count > 0: // interesting byte
                {
                    byte[] values = [0x00, 0xFF, 0x7F, 0x80, 0x01, (byte)'0', (byte)'9', (byte)' ', (byte)'\n', (byte)'/'];
                    data[Pos()] = values[_random.Next(values.Length)];
                    break;
                }

            case 2: // insert token
                data.InsertRange(Pos(1), Tokens[_random.Next(Tokens.Length)]);
                break;

            case 3 when data.Count > 1: // delete range
                {
                    int p = Pos();
                    int n = Math.Min(data.Count - p, 1 + _random.Next(Math.Max(1, data.Count / 16)));
                    data.RemoveRange(p, n);
                    break;
                }

            case 4 when data.Count > 1: // duplicate range
                {
                    int p = Pos();
                    int n = Math.Min(data.Count - p, 1 + _random.Next(256));
                    data.InsertRange(Pos(1), data.GetRange(p, n));
                    break;
                }

            case 5 when data.Count > 1: // truncate
                {
                    int keep = _random.Next(data.Count);
                    data.RemoveRange(keep, data.Count - keep);
                    break;
                }

            case 6: // replace a decimal number with an extreme one
                ReplaceNumber(data);
                break;

            case 7 when _corpus.Count > 1: // splice with another corpus entry
                {
                    byte[] other = _corpus[_random.Next(_corpus.Count)];
                    if (other.Length > 0)
                    {
                        int from = _random.Next(other.Length);
                        int n = Math.Min(other.Length - from, 1 + _random.Next(4096));
                        data.InsertRange(Pos(1), other.AsSpan(from, n).ToArray());
                    }

                    break;
                }

            case 8: // repeat a token many times (nesting)
                {
                    byte[] token = Tokens[_random.Next(Tokens.Length)];
                    int repeat = 2 + _random.Next(2000);
                    var block = new byte[token.Length * repeat];
                    for (int i = 0; i < repeat; i++)
                    {
                        token.CopyTo(block, i * token.Length);
                    }

                    data.InsertRange(Pos(1), block);
                    break;
                }

            default: // random bytes
                {
                    byte[] chunk = new byte[1 + _random.Next(32)];
                    _random.NextBytes(chunk);
                    data.InsertRange(Pos(1), chunk);
                    break;
                }
        }
    }

    private void ReplaceNumber(List<byte> data)
    {
        if (data.Count == 0)
        {
            return;
        }

        int start = _random.Next(data.Count);
        int p = start;
        while (p < data.Count && !(data[p] >= '0' && data[p] <= '9'))
        {
            p++;
            if (p - start > 4096)
            {
                return;
            }
        }

        if (p >= data.Count)
        {
            return;
        }

        int end = p;
        while (end < data.Count && data[end] >= '0' && data[end] <= '9')
        {
            end++;
        }

        string[] numbers = ["0", "-1", "1", "2147483647", "2147483648", "4294967295", "-2147483648", "9223372036854775807", "99999999999999999999", "65535", "4096"];
        data.RemoveRange(p, end - p);
        data.InsertRange(p, Encoding.ASCII.GetBytes(numbers[_random.Next(numbers.Length)]));
    }
}
