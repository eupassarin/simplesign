using BenchmarkDotNet.Running;

namespace SimpleSign.Benchmarks;

internal static class Program
{
    private static void Main(string[] args) =>
        BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
}
