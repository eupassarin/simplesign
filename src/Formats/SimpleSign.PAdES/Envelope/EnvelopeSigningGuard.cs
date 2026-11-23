using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES.Signing;

namespace SimpleSign.PAdES.Envelope;

/// <summary>How a signature is configured, for the checks of an envelope's field before signing.</summary>
/// <param name="Level">The baseline level the signature is made at.</param>
/// <param name="SubFilter">Its SubFilter.</param>
/// <param name="PolicyOid">Its signature policy; null when none.</param>
/// <param name="Certification">The certification it makes; null when none.</param>
/// <param name="Hash">Its digest algorithm.</param>
internal sealed record EnvelopeSignatureSettings(
    AdesBaselineLevel Level, PdfSignatureSubFilter SubFilter, string? PolicyOid, CertificationLevel? Certification, HashAlgorithmName Hash);

/// <summary>
/// The checks made before signing a field of an envelope (ADR 0033 point 6): the signer and the turn
/// (<see cref="PdfEnvelope.CheckSigner"/>), then the field's seed values and the level, against how the signature is
/// configured. Nothing is applied: what falls short is refused.
/// </summary>
internal static class EnvelopeSigningGuard
{
    /// <summary>Checks, and returns the signer the manifest gives the field.</summary>
    /// <exception cref="SigningException">The field may not be signed so: <see cref="SigningException.Reason"/> says why.</exception>
    public static EnvelopeManifestSigner Ensure(
        ReadOnlyMemory<byte> pdf, string field, X509Certificate2 certificate, IEnumerable<ISignerIdentityReader> readers, EnvelopeSignatureSettings settings)
    {
        var envelope = PdfEnvelopeReader.Read(pdf)
            ?? throw new SigningException("The PDF holds no signature envelope.", SigningErrorReason.EnvelopeFieldNotFound);
        var check = PdfEnvelope.CheckSignerCore(envelope, field, certificate, readers);
        if (check.Reason is { } reason)
        {
            throw new SigningException(check.Message ?? reason.ToString(), reason);
        }

        var signer = check.Signer!;
        var info = envelope.Fields.First(f => f.Name == field);
        var level = signer.Level;
        if ((level.Timestamp || info.SeedValue?.TimestampRequired == true) && settings.Level < AdesBaselineLevel.Timestamped)
        {
            throw new SigningException(
                $"The field '{field}' needs a signature time-stamp (level {level.Id}): sign at B-T or above.", SigningErrorReason.TimestampRequired);
        }

        if (settings.Level < level.Baseline)
        {
            throw new SigningException(
                $"The field '{field}' needs level {level.Id} ({EnvelopeManifestJson.BaselineText(level.Baseline)}); the signature is configured at {EnvelopeManifestJson.BaselineText(settings.Level)}.",
                SigningErrorReason.LevelNotMet);
        }

        string subFilter = SubFilterName(settings.SubFilter);
        if (level.SubFilters.Count > 0 && !level.SubFilters.Contains(subFilter, StringComparer.Ordinal))
        {
            throw new SigningException(
                $"The field '{field}' needs level {level.Id}, signed with {string.Join(" or ", level.SubFilters)}; the signature is configured with {subFilter}.",
                SigningErrorReason.LevelNotMet);
        }

        if (level.PolicyOids.Count > 0 && (settings.PolicyOid is null || !level.PolicyOids.Contains(settings.PolicyOid, StringComparer.Ordinal)))
        {
            throw new SigningException(
                $"The field '{field}' needs level {level.Id}, under the signature policy {string.Join(" or ", level.PolicyOids)}; the signature is configured with {settings.PolicyOid ?? "none"}.",
                SigningErrorReason.LevelNotMet);
        }

        if (info.SeedValue?.CertificationPermissions is int permissions && (int?)settings.Certification != permissions)
        {
            throw new SigningException(
                $"The field '{field}' asks the signer to certify the document with P={permissions} (AsCertification).",
                SigningErrorReason.SeedValueViolated);
        }

        if (info.SeedValue is { DigestMethods.Count: > 0 } seedValue
            && !seedValue.DigestMethods.Contains(settings.Hash.Name ?? "", StringComparer.OrdinalIgnoreCase))
        {
            throw new SigningException(
                $"The field '{field}' accepts the digests {string.Join(", ", seedValue.DigestMethods)}; the signature is configured with {settings.Hash.Name}.",
                SigningErrorReason.SeedValueViolated);
        }

        return signer;
    }

    /// <summary>The roles to claim: the caller's, else the manifest's role of the signer.</summary>
    public static IReadOnlyList<string> Roles(IReadOnlyList<string> given, EnvelopeManifestSigner signer) =>
        given.Count > 0 || string.IsNullOrWhiteSpace(signer.Role) ? given : [signer.Role];

    /// <summary>The SubFilter's name as the signature dictionary writes it.</summary>
    public static string SubFilterName(PdfSignatureSubFilter subFilter) => subFilter switch
    {
        PdfSignatureSubFilter.EtsiCadesDetached => "ETSI.CAdES.detached",
        PdfSignatureSubFilter.PbadPades => "PBAD.PAdES",
        _ => "adbe.pkcs7.detached",
    };
}
