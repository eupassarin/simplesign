namespace SimpleSign.TestBench.Matrix;

/// <summary>
/// Case generation shared by the run matrices: every value on its own (with compatible partners
/// when the defaults are not), then greedy pairwise cases so every pair of values that can go
/// together is tried at least once.
/// </summary>
internal static class Pairwise
{
    /// <summary>Generates the cases.</summary>
    /// <param name="dims">The values of each dimension; the first is the default.</param>
    /// <param name="valid">Whether an assignment (one value per dimension) is allowed by the rules.</param>
    /// <param name="maxCases">Upper bound on the number of cases.</param>
    /// <param name="uncoverable">Pairs that no valid assignment can cover.</param>
    /// <returns>The cases as (group, values) with group "single" or "pairwise".</returns>
    public static IReadOnlyList<(string Group, string[] Values)> Generate(
        IReadOnlyList<IReadOnlyList<string>> dims, Func<string[], bool> valid, int maxCases, out int uncoverable)
    {
        var defaults = dims.Select(d => d[0]).ToArray();
        var cases = new List<(string, string[])>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var random = new Random(3161);

        void Add(string group, string[] values)
        {
            if (seen.Add(string.Join("|", values)))
            {
                cases.Add((group, values));
            }
        }

        // 1. Every value on its own.
        for (int d = 0; d < dims.Count; d++)
        {
            foreach (string value in dims[d])
            {
                var values = (string[])defaults.Clone();
                values[d] = value;
                for (int attempt = 0; attempt < 300 && !valid(values); attempt++)
                {
                    values = RandomAssignment(dims, random);
                    values[d] = value;
                }

                if (valid(values))
                {
                    Add("single", values);
                }
            }
        }

        // 2. Pairwise: greedily pick valid candidates that cover the most uncovered pairs.
        var uncovered = new HashSet<(int, string, int, string)>();
        for (int a = 0; a < dims.Count; a++)
        {
            for (int b = a + 1; b < dims.Count; b++)
            {
                foreach (string va in dims[a])
                {
                    foreach (string vb in dims[b])
                    {
                        uncovered.Add((a, va, b, vb));
                    }
                }
            }
        }

        foreach (var (_, values) in cases)
        {
            Cover(uncovered, values);
        }

        int stale = 0;
        int impossible = 0;
        while (uncovered.Count > 0 && stale < 40 && cases.Count < maxCases)
        {
            string[]? best = null;
            int bestGain = 0;
            var target = uncovered.ElementAt(random.Next(uncovered.Count));
            for (int candidate = 0; candidate < 60; candidate++)
            {
                var values = RandomAssignment(dims, random);
                values[target.Item1] = target.Item2;
                values[target.Item3] = target.Item4;
                int gain = Gain(uncovered, values);
                if (gain > bestGain && valid(values))
                {
                    best = values;
                    bestGain = gain;
                }
            }

            if (best is null)
            {
                uncovered.Remove(target); // never valid together (e.g. adbe.pkcs7.detached + B-T)
                impossible++;
                stale++;
                continue;
            }

            stale = 0;
            Add("pairwise", best);
            Cover(uncovered, best);
        }

        uncoverable = impossible + uncovered.Count;
        return cases;
    }

    private static string[] RandomAssignment(IReadOnlyList<IReadOnlyList<string>> dims, Random random) =>
        [.. dims.Select(d => d[random.Next(d.Count)])];

    private static int Gain(HashSet<(int, string, int, string)> uncovered, string[] values)
    {
        int gain = 0;
        for (int a = 0; a < values.Length; a++)
        {
            for (int b = a + 1; b < values.Length; b++)
            {
                if (uncovered.Contains((a, values[a], b, values[b])))
                {
                    gain++;
                }
            }
        }

        return gain;
    }

    private static void Cover(HashSet<(int, string, int, string)> uncovered, string[] values)
    {
        for (int a = 0; a < values.Length; a++)
        {
            for (int b = a + 1; b < values.Length; b++)
            {
                uncovered.Remove((a, values[a], b, values[b]));
            }
        }
    }
}
