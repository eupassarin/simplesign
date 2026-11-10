using SimpleSign.Cli.Rendering;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES.Signing;

namespace SimpleSign.Cli.Commands;

/// <summary>
/// The level, TSA and signature-field options that <c>sign</c>, <c>sign-dir</c> and <c>deferred prepare</c>
/// share: their checks and the <see cref="AdesBaselineProfile"/> and <see cref="SignatureFieldOptions"/> they build.
/// </summary>
internal static class PadesProfileOptions
{
    /// <summary>The level options of a PAdES command.</summary>
    internal sealed record Level(string? TsaUrl, bool Ltv, bool Archival, string? ArchiveTsaUrl, bool ReturnLowerLevel, string? RevocationPreference);

    /// <summary>The error for inconsistent level options, or null.</summary>
    internal static string? Validate(Level level)
    {
        if (level.Ltv && string.IsNullOrWhiteSpace(level.TsaUrl))
        {
            return "--ltv requires --tsa. LTV without a timestamp is not valid for long-term archival.";
        }

        if (level.Archival && string.IsNullOrWhiteSpace(level.TsaUrl))
        {
            return "--archival requires --tsa: the signature and archive timestamps come from it.";
        }

        if (level.ArchiveTsaUrl is not null && !level.Archival)
        {
            return "--archive-tsa requires --archival.";
        }

        return level.ReturnLowerLevel && string.IsNullOrWhiteSpace(level.TsaUrl)
            ? "--return-lower-level requires --tsa: only the timestamp and the revocation data can fall short."
            : AdesOptionSupport.ValidateRevocationPreference(level.RevocationPreference);
    }

    /// <summary>The error for an unknown <c>--hash</c>, <c>--signature-algorithm</c> or an out-of-range <c>--contents-size</c>, or null.</summary>
    internal static string? ValidateCrypto(string? hash, string? signatureAlgorithm, int? contentsSize)
    {
        if (hash is not null && !IsKnownHash(hash))
        {
            return "--hash must be SHA256, SHA384, SHA512, SHA3-256, SHA3-384, or SHA3-512.";
        }

        if (signatureAlgorithm is not null && SignCommandOptions.ParseSignatureAlgorithm(signatureAlgorithm) is null)
        {
            return "--signature-algorithm must be rsa-pkcs1 or rsassa-pss.";
        }

        return contentsSize is < 1024 or > 1_048_576 ? "--contents-size must be between 1024 and 1048576 bytes." : null;
    }

    /// <summary>The baseline profile of the level options: B-B without a TSA, else B-T, B-LT or B-LTA.</summary>
    internal static AdesBaselineProfile Build(Level level, TimestampedSigningSettings credentials)
    {
        if (string.IsNullOrWhiteSpace(level.TsaUrl))
        {
            return AdesBaselineProfile.Basic();
        }

        var timestamp = credentials.Timestamp(level.TsaUrl);
        var failure = level.ReturnLowerLevel ? SigningLevelFailureBehavior.ReturnLowerLevel : SigningLevelFailureBehavior.Throw;
        if (!level.Ltv && !level.Archival)
        {
            return AdesBaselineProfile.Timestamped(timestamp, failure);
        }

        var validation = AdesOptionSupport.LongTermOptions(level.RevocationPreference);
        if (!level.Archival)
        {
            return AdesBaselineProfile.LongTerm(timestamp, validation, failure);
        }

        var archive = level.ArchiveTsaUrl is null ? null : credentials.ArchiveTimestamp(level.ArchiveTsaUrl);
        return AdesBaselineProfile.Archive(timestamp, validation, archive, failure);
    }

    /// <summary>The signature field: its name, the declared signer, reason, location and contact, and the reserved /Contents.</summary>
    internal static SignatureFieldOptions Field(
        string? fieldName, string? signerName, string? reason, string? location, string? contact, int? contentsSize) => new()
        {
            FieldName = fieldName ?? "Signature1",
            SignerName = signerName,
            Reason = reason,
            Location = location,
            ContactInfo = contact,
            ContentsReservedBytes = contentsSize ?? PdfSignatureWriter.DefaultContentsReservedBytes,
        };

    private static bool IsKnownHash(string hash) =>
        hash.ToUpperInvariant() is "SHA256" or "SHA384" or "SHA512" or "SHA3-256" or "SHA3-384" or "SHA3-512";
}
