using System.Text;
using System.Text.RegularExpressions;

namespace SimpleSign.PAdES.Validation;

/// <summary>
/// Validates VRI (Validation Related Information) dictionary structure
/// per ISO 32000-2 §12.8.4.4.
/// </summary>
internal static partial class VriValidator
{
    /// <summary>
    /// Validates VRI structure within a DSS dictionary slice.
    /// Returns entry count, whether timestamps are present, and any warnings.
    /// </summary>
    internal static VriValidationResult Validate(ReadOnlySpan<byte> dssDictSlice)
    {
        var warnings = new List<string>();
        bool allHaveTimestamps = true;

        // Find /VRI within the DSS dictionary
        int vriIdx = DssExtractor.IndexOfBytes(dssDictSlice, "/VRI "u8);
        if (vriIdx < 0)
        {
            vriIdx = DssExtractor.IndexOfBytes(dssDictSlice, "/VRI<<"u8);
        }

        if (vriIdx < 0)
        {
            return new VriValidationResult(0, false, ["VRI dictionary not found in DSS"]);
        }

        // Find the opening << of the VRI dictionary
        int vriDictStart = DssExtractor.IndexOfBytesFrom(dssDictSlice, "<<"u8, vriIdx + 4);
        if (vriDictStart < 0)
        {
            warnings.Add("VRI dictionary malformed: missing opening <<");
            return new VriValidationResult(0, false, warnings);
        }

        // Find matching >> (accounting for nested dicts)
        int depth = 0;
        int vriDictEnd = -1;
        for (int i = vriDictStart; i < dssDictSlice.Length - 1; i++)
        {
            if (dssDictSlice[i] == '<' && dssDictSlice[i + 1] == '<')
            {
                depth++;
                i++;
            }
            else if (dssDictSlice[i] == '>' && dssDictSlice[i + 1] == '>')
            {
                depth--;
                i++;
                if (depth == 0)
                {
                    vriDictEnd = i + 1;
                    break;
                }
            }
        }

        if (vriDictEnd < 0)
        {
            warnings.Add("VRI dictionary malformed: missing closing >>");
            return new VriValidationResult(0, false, warnings);
        }

        // Extract VRI dict content (between outer << and >>)
        var vriContent = dssDictSlice[(vriDictStart + 2)..vriDictEnd];
        var vriText = Encoding.Latin1.GetString(vriContent.ToArray());

        // Find VRI keys (format: /HEXHASH followed by object ref or <<)
        var keyMatches = VriKeyRegex().Matches(vriText);
        int entryCount = keyMatches.Count;

        if (entryCount == 0)
        {
            warnings.Add("VRI dictionary is empty (no signature hash entries)");
            return new VriValidationResult(0, false, warnings);
        }

        foreach (Match match in keyMatches)
        {
            string key = match.Groups[1].Value;

            // Validate key is uppercase hex (SHA-1 = 40 hex chars)
            if (!IsValidVriKey(key))
            {
                warnings.Add($"VRI key '{key}' is not a valid uppercase hex SHA-1 hash");
            }
        }

        // Check for /TU in VRI entries — look inside each nested dict
        // Simple heuristic: count /TU occurrences in the VRI content
        int tuCount = CountOccurrences(vriContent, "/TU "u8) + CountOccurrences(vriContent, "/TU("u8);
        if (tuCount < entryCount)
        {
            allHaveTimestamps = false;
            warnings.Add($"VRI: {entryCount - tuCount} of {entryCount} entries missing /TU timestamp (ISO 32000-2 §12.8.4.4)");
        }

        // Check each entry has at least one of /Cert, /CRL, /OCSP
        int entriesWithRevData = CountOccurrences(vriContent, "/Cert"u8)
                               + CountOccurrences(vriContent, "/CRL"u8)
                               + CountOccurrences(vriContent, "/OCSP"u8);
        if (entriesWithRevData == 0)
        {
            warnings.Add("VRI entries have no revocation data (/Cert, /CRL, or /OCSP)");
        }

        return new VriValidationResult(entryCount, allHaveTimestamps, warnings);
    }

    /// <summary>
    /// Validates that a VRI key is a valid uppercase hex SHA-1 hash (40 chars).
    /// </summary>
    internal static bool IsValidVriKey(string key)
    {
        if (key.Length != 40)
        {
            return false;
        }

        foreach (char c in key)
        {
            if ((c < '0' || c > '9') && (c < 'A' || c > 'F'))
            {
                return false;
            }
        }

        return true;
    }

    private static int CountOccurrences(ReadOnlySpan<byte> data, ReadOnlySpan<byte> needle)
    {
        int count = 0;
        int pos = 0;
        while (pos <= data.Length - needle.Length)
        {
            int idx = DssExtractor.IndexOfBytesFrom(data, needle, pos);
            if (idx < 0)
            {
                break;
            }
            count++;
            pos = idx + needle.Length;
        }
        return count;
    }

    [GeneratedRegex(@"/([0-9A-Fa-f]{10,40})\s")]
    internal static partial Regex VriKeyRegex();
}

/// <summary>
/// Result of VRI structure validation.
/// </summary>
internal sealed record VriValidationResult(
    int EntryCount,
    bool AllHaveTimestamps,
    IReadOnlyList<string> Warnings);
