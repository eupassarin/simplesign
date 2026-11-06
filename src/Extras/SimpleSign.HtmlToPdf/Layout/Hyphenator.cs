namespace SimpleSign.HtmlToPdf.Layout;

/// <summary>
/// Rule-based syllable hyphenation for Portuguese and Spanish (<c>hyphens: auto</c>).
/// Romance-language syllabification is regular enough to need no dictionary: consonant
/// clusters and digraphs decide where a syllable starts.
/// </summary>
internal static class Hyphenator
{
    private const int MinBefore = 2;
    private const int MinAfter = 2;
    private const int MinWord = 5;

    // Consonant pairs that always begin a syllable together (a-bra-ço, re-tra-to).
    private static readonly HashSet<string> Onsets = new(StringComparer.Ordinal)
    {
        "bl", "br", "cl", "cr", "dr", "fl", "fr", "gl", "gr", "pl", "pr", "tr", "vr", "tl",
        "ch", "lh", "nh", "ll",
    };

    /// <summary>Returns true when automatic hyphenation is available for a language tag.</summary>
    public static bool Supports(string? language) =>
        language is { Length: >= 2 } lang && (lang.StartsWith("pt", StringComparison.OrdinalIgnoreCase) || lang.StartsWith("es", StringComparison.OrdinalIgnoreCase));

    /// <summary>Gets the indices inside <paramref name="word"/> where a hyphen may be inserted.</summary>
    public static List<int> Points(string word, string? language)
    {
        var points = new List<int>();
        if (!Supports(language) || word.Length < MinWord)
        {
            return points;
        }

        // Only hyphenate the alphabetic core; leading/trailing punctuation stays attached.
        int start = 0, end = word.Length;
        while (start < end && !char.IsLetter(word[start]))
        {
            start++;
        }

        while (end > start && !char.IsLetter(word[end - 1]))
        {
            end--;
        }

        string core = word[start..end].ToLowerInvariant();
        if (core.Length < MinWord || core.Any(c => !char.IsLetter(c)))
        {
            return points;
        }

        bool[] vowel = Classify(core);
        int i = 0;

        // Skip to the first vowel nucleus.
        while (i < core.Length && !vowel[i])
        {
            i++;
        }

        while (i < core.Length)
        {
            // Advance over the vowel group.
            while (i < core.Length && vowel[i])
            {
                i++;
            }

            int consonantsStart = i;
            while (i < core.Length && !vowel[i])
            {
                i++;
            }

            if (i >= core.Length)
            {
                break; // trailing consonants belong to the last syllable
            }

            int count = i - consonantsStart;
            int split = count switch
            {
                0 => -1,
                1 => consonantsStart,
                2 => IsOnset(core, consonantsStart) ? consonantsStart : consonantsStart + 1,
                _ => IsOnset(core, i - 2) ? i - 2 : i - 1,
            };

            if (split >= MinBefore && core.Length - split >= MinAfter)
            {
                points.Add(start + split);
            }
        }

        return points;
    }

    private static bool IsOnset(string word, int index) =>
        index + 1 < word.Length && Onsets.Contains(word.Substring(index, 2));

    /// <summary>Marks vowel nuclei; the u of qu/gu before a vowel is part of the consonant.</summary>
    private static bool[] Classify(string word)
    {
        var vowel = new bool[word.Length];
        for (int i = 0; i < word.Length; i++)
        {
            vowel[i] = IsVowel(word[i]);
        }

        for (int i = 1; i + 1 < word.Length; i++)
        {
            if (word[i] is 'u' or 'ü' && word[i - 1] is 'q' or 'g' && IsVowel(word[i + 1]))
            {
                vowel[i] = false;
            }
        }

        // y between vowels (Spanish "mayo") acts as a consonant.
        for (int i = 1; i + 1 < word.Length; i++)
        {
            if (word[i] == 'y' && vowel[i - 1] && IsVowel(word[i + 1]))
            {
                vowel[i] = false;
            }
        }

        return vowel;
    }

    private static bool IsVowel(char c) => c is 'a' or 'e' or 'i' or 'o' or 'u' or 'y'
        or 'á' or 'à' or 'â' or 'ã' or 'é' or 'ê' or 'í' or 'ó' or 'ô' or 'õ' or 'ú' or 'ü';
}
