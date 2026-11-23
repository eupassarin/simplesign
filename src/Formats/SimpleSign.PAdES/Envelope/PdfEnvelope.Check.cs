using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Signing;

namespace SimpleSign.PAdES.Envelope;

/// <summary>How an identifier of an envelope's signer compares with a certificate.</summary>
public enum EnvelopeIdentifierMatch
{
    /// <summary>The certificate carries the value.</summary>
    Matched = 0,

    /// <summary>The certificate does not carry the value (a reader knows the type, and read another value or none).</summary>
    Mismatch = 1,

    /// <summary>No identity reader of the profile knows the type: the certificate cannot be checked against it.</summary>
    NotVerifiable = 2,
}

/// <summary>One identifier of a signer compared with a certificate.</summary>
/// <param name="Identifier">The identifier the manifest asks for.</param>
/// <param name="Match">How it compares.</param>
/// <param name="Found">The values the certificate carries for its types.</param>
public sealed record EnvelopeIdentifierCheck(EnvelopeIdentifier Identifier, EnvelopeIdentifierMatch Match, IReadOnlyList<string> Found);

/// <summary>Whether a certificate may sign a field of an envelope now, and why not (<see cref="PdfEnvelope.CheckSigner"/>).</summary>
public sealed record EnvelopeCheck
{
    /// <summary>The field.</summary>
    public required string Field { get; init; }

    /// <summary>Whether the certificate may sign the field now.</summary>
    public bool Allowed => Reason is null;

    /// <summary>Why it may not: <see cref="SigningErrorReason.EnvelopeFieldNotFound"/>, <see cref="SigningErrorReason.EnvelopeFieldAlreadySigned"/>,
    /// <see cref="SigningErrorReason.NotYourTurn"/>, <see cref="SigningErrorReason.UnexpectedSigner"/> or <see cref="SigningErrorReason.EnvelopeTampered"/>; null when it may.</summary>
    public SigningErrorReason? Reason { get; init; }

    /// <summary>What <see cref="Reason"/> means here, for people; null when allowed.</summary>
    public string? Message { get; init; }

    /// <summary>The signer the manifest gives the field; null when the field is not in it.</summary>
    public EnvelopeManifestSigner? Signer { get; init; }

    /// <summary>Each identifier of the signer compared with the certificate.</summary>
    public IReadOnlyList<EnvelopeIdentifierCheck> Identifiers { get; init; } = [];

    /// <summary>Whether every field before this one is signed, in a sequential envelope; true in a parallel one.</summary>
    public bool IsYourTurn { get; init; }
}

public static partial class PdfEnvelope
{
    /// <summary>
    /// Whether <paramref name="certificate"/> may sign <paramref name="field"/> now: the field is in the envelope and
    /// not signed, it is the signer's turn (sequential order), the envelope is consistent, and the certificate carries
    /// every identifier the manifest gives the signer. It reads the certificate only, so it runs before the PIN is
    /// asked; the level is checked when signing.
    /// </summary>
    /// <param name="pdf">The document with the envelope.</param>
    /// <param name="field">The field, such as <c>SimpleSign_2</c>.</param>
    /// <param name="certificate">The signer's certificate.</param>
    /// <param name="profile">The trust profile whose identity readers read the certificate (CPF, CNPJ…), besides <see cref="DefaultSignerIdentityReader"/>; null: that one only.</param>
    /// <returns>The answer, with each identifier compared.</returns>
    /// <exception cref="SigningException">The document holds no envelope (<see cref="SigningErrorReason.EnvelopeFieldNotFound"/>).</exception>
    public static EnvelopeCheck CheckSigner(ReadOnlyMemory<byte> pdf, string field, X509Certificate2 certificate, TrustProfile? profile = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(field);
        ArgumentNullException.ThrowIfNull(certificate);
        var envelope = PdfEnvelopeReader.Read(pdf)
            ?? throw new SigningException("The PDF holds no signature envelope.", SigningErrorReason.EnvelopeFieldNotFound);
        return CheckSignerCore(envelope, field, certificate, profile?.SignerIdentityReaders ?? []);
    }

    /// <summary>The check of <see cref="CheckSigner(ReadOnlyMemory{byte}, string, X509Certificate2, TrustProfile?)"/> on an envelope already read.</summary>
    internal static EnvelopeCheck CheckSignerCore(PdfEnvelopeInfo envelope, string field, X509Certificate2 certificate, IEnumerable<ISignerIdentityReader> readers)
    {
        var info = envelope.Fields.FirstOrDefault(f => f.Name == field);
        var signer = info?.Signer;
        if (envelope.Status == EnvelopeStatus.Inconsistent)
        {
            return Refused(field, signer, SigningErrorReason.EnvelopeTampered,
                $"The envelope's fields and manifest do not agree: {string.Join(" ", envelope.Problems)}");
        }

        if (info is null || signer is null || !info.Exists)
        {
            return Refused(field, signer, SigningErrorReason.EnvelopeFieldNotFound, $"The envelope has no field '{field}'.");
        }

        if (info.IsSigned)
        {
            return Refused(field, signer, SigningErrorReason.EnvelopeFieldAlreadySigned, $"The field '{field}' is already signed.");
        }

        var allReaders = readers.Append(DefaultSignerIdentityReader.Instance).Distinct().ToList();
        var identifiers = signer.Identifiers.Select(i => Compare(i, certificate, allReaders)).ToList();
        bool turn = envelope.Manifest?.Order != EnvelopeOrder.Sequential
            || envelope.Fields.TakeWhile(f => f.Name != field).All(f => f.IsSigned);
        var check = new EnvelopeCheck { Field = field, Signer = signer, Identifiers = identifiers, IsYourTurn = turn };
        if (!turn)
        {
            string waiting = string.Join(", ", envelope.Fields.TakeWhile(f => f.Name != field).Where(f => !f.IsSigned).Select(f => $"{f.Name} ({f.Signer?.Name})"));
            return check with { Reason = SigningErrorReason.NotYourTurn, Message = $"The field '{field}' is signed after {waiting}." };
        }

        if (identifiers.FirstOrDefault(i => i.Match != EnvelopeIdentifierMatch.Matched) is { } failed)
        {
            string message = failed.Match == EnvelopeIdentifierMatch.NotVerifiable
                ? $"The certificate cannot be checked for the {failed.Identifier.Type} of {signer.Name}: no identity reader of the profile knows that type. Sign with the profile of the framework that issues it."
                : $"The certificate is not {signer.Name}'s: it does not carry the {failed.Identifier.Type} {failed.Identifier.Value}.";
            return check with { Reason = SigningErrorReason.UnexpectedSigner, Message = message };
        }

        return check;
    }

    private static EnvelopeCheck Refused(string field, EnvelopeManifestSigner? signer, SigningErrorReason reason, string message) =>
        new() { Field = field, Signer = signer, Reason = reason, Message = message };

    private static EnvelopeIdentifierCheck Compare(EnvelopeIdentifier identifier, X509Certificate2 certificate, List<ISignerIdentityReader> readers)
    {
        var types = new[] { identifier.Type }.Concat(identifier.AlsoAccept).ToList();
        var found = new List<string>();
        bool known = false;
        foreach (string type in types)
        {
            foreach (var reader in readers.Where(r => r.IdentifierTypes.Contains(type, StringComparer.OrdinalIgnoreCase)))
            {
                known = true;
                found.AddRange(reader.Read(certificate, type));
            }
        }

        var match = !known ? EnvelopeIdentifierMatch.NotVerifiable
            : found.Any(v => SameValue(identifier.Type, identifier.Value, v)) ? EnvelopeIdentifierMatch.Matched
            : EnvelopeIdentifierMatch.Mismatch;
        return new EnvelopeIdentifierCheck(identifier, match, [.. found.Distinct(StringComparer.OrdinalIgnoreCase)]);
    }

    /// <summary>An email is compared as written, without regard to case; another identifier also without dots, hyphens, slashes and spaces.</summary>
    internal static bool SameValue(string type, string expected, string actual) =>
        string.Equals(type, SignerIdentifierTypes.Email, StringComparison.OrdinalIgnoreCase)
            ? string.Equals(expected.Trim(), actual.Trim(), StringComparison.OrdinalIgnoreCase)
            : string.Equals(Plain(expected), Plain(actual), StringComparison.OrdinalIgnoreCase);

    private static string Plain(string value) => string.Concat(value.Where(c => c is not ('.' or '-' or '/' or ' ')));
}
