using System.Text.RegularExpressions;

namespace SimpleSign.PAdES.Validation;

/// <summary>
/// Validates VRI (Validation Related Information) dictionary structure
/// per ISO 32000-2 §12.8.4.4.
/// </summary>
internal static partial class VriValidator
{
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
