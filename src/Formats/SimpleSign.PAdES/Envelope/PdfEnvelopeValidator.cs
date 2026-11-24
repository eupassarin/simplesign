using System.Text.Json;
using System.Text.Json.Serialization;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Validation;

namespace SimpleSign.PAdES.Envelope;

/// <summary>A field of an envelope, validated (<see cref="PdfEnvelopeValidator"/>).</summary>
public sealed record EnvelopeSignatureReport
{
    /// <summary>The field.</summary>
    public required string Field { get; init; }

    /// <summary>The signer the manifest gives the field.</summary>
    public EnvelopeManifestSigner? Signer { get; init; }

    /// <summary>Whether the field is signed.</summary>
    public bool IsSigned { get; init; }

    /// <summary>The signature's validation, as <see cref="PdfSignatureValidator"/> gives it; null when not signed.</summary>
    public SignatureValidationResult? Validation { get; init; }

    /// <summary>Each identifier of the signer compared with the signing certificate; empty when not signed.</summary>
    public IReadOnlyList<EnvelopeIdentifierCheck> Identifiers { get; init; } = [];

    /// <summary>Whether the signing certificate carries every identifier of the signer.</summary>
    public bool SignerMatches { get; init; }

    /// <summary>The baseline level the signature reaches, from what it holds; null when below B-B or not signed.</summary>
    public AdesBaselineLevel? ReachedLevel { get; init; }

    /// <summary>Whether the signature meets the level the manifest asks for.</summary>
    public bool LevelMet { get; init; }

    /// <summary>What falls short of the level; empty when it is met.</summary>
    public IReadOnlyList<string> LevelProblems { get; init; } = [];

    /// <summary>Whether it was signed after every field before it, in a sequential envelope; true in a parallel one.</summary>
    public bool InOrder { get; init; }

    /// <summary>Whether the field is signed, the signature is valid (<see cref="SignatureIndication.Valid"/>), by the signer, at the level and in order.</summary>
    public bool IsComplete => IsSigned && Validation?.Indication == SignatureIndication.Valid && SignerMatches && LevelMet && InOrder;
}

/// <summary>An envelope validated (<see cref="PdfEnvelopeValidator"/>): each field, and the envelope as a whole.</summary>
public sealed record PdfEnvelopeReport
{
    /// <summary>The envelope as read.</summary>
    public required PdfEnvelopeInfo Envelope { get; init; }

    /// <summary>Each field of the manifest, in its order.</summary>
    public IReadOnlyList<EnvelopeSignatureReport> Signatures { get; init; } = [];

    /// <summary>The fields not signed yet.</summary>
    public IReadOnlyList<string> MissingFields => [.. Signatures.Where(s => !s.IsSigned).Select(s => s.Field)];

    /// <summary>Whether every signature came in the manifest's order (always, in a parallel envelope).</summary>
    public bool OrderRespected => Signatures.All(s => s.InOrder);

    /// <summary>Whether the fields and the manifest agree, and the manifest is the one the first signature covered.</summary>
    public bool ManifestUnchanged => Envelope.Status != EnvelopeStatus.Inconsistent;

    /// <summary>Whether the envelope is complete: consistent, and every field signed validly, by its signer, at its level, in order.</summary>
    public bool IsComplete => ManifestUnchanged && Signatures.Count > 0 && Signatures.All(s => s.IsComplete);

    /// <summary>The report as JSON (camel case, indented), for a log or another program.</summary>
    public string ToJson()
    {
        var dto = new EnvelopeReportDto
        {
            Id = Envelope.Manifest?.Id,
            Status = Envelope.Status.ToString(),
            IsComplete = IsComplete,
            OrderRespected = OrderRespected,
            ManifestUnchanged = ManifestUnchanged,
            MissingFields = [.. MissingFields],
            Problems = [.. Envelope.Problems],
            Signatures = [.. Signatures.Select(s => new EnvelopeSignatureReportDto
            {
                Field = s.Field,
                Signer = s.Signer?.Name,
                IsSigned = s.IsSigned,
                Indication = s.Validation?.Indication.ToString(),
                SubIndication = s.Validation?.SubIndication?.ToString(),
                SignerCertificate = s.Validation?.SignerCertificate?.Subject,
                SigningTime = s.Validation?.BestSignatureTime ?? s.Validation?.SigningTime,
                SignerMatches = s.SignerMatches,
                Identifiers = [.. s.Identifiers.Select(i => new EnvelopeIdentifierReportDto { Type = i.Identifier.Type, Value = i.Identifier.Value, Match = i.Match.ToString() })],
                Level = s.Signer?.Level.Id,
                ReachedLevel = s.ReachedLevel is { } reached ? EnvelopeManifestJson.BaselineText(reached) : null,
                LevelMet = s.LevelMet,
                LevelProblems = [.. s.LevelProblems],
                InOrder = s.InOrder,
                IsComplete = s.IsComplete,
            })],
        };
        return JsonSerializer.Serialize(dto, EnvelopeReportJsonContext.Default.EnvelopeReportDto);
    }
}

/// <summary>
/// Validates an envelope (ADR 0033): every signature as <see cref="PdfSignatureValidator"/> does, and, for each field of
/// the manifest, whether it is signed, by the signer (every identifier, read by the profile's identity readers), at
/// the level, and in order; and whether the manifest is unchanged.
/// </summary>
public sealed class PdfEnvelopeValidator
{
    private readonly PdfSignatureValidator _validator;
    private readonly IReadOnlyList<ISignerIdentityReader> _readers;

    /// <summary>Creates a validator.</summary>
    /// <param name="options">How the signatures are validated; its <see cref="ValidationOptions.Profile"/> also gives the identity readers.</param>
    public PdfEnvelopeValidator(ValidationOptions? options = null)
        : this(new PdfSignatureValidator(options ?? new ValidationOptions()), options?.Profile?.SignerIdentityReaders)
    {
    }

    /// <summary>Creates a validator that validates the signatures with <paramref name="validator"/>.</summary>
    /// <param name="validator">The signature validator.</param>
    /// <param name="identityReaders">The identity readers (CPF, CNPJ…), besides <see cref="DefaultSignerIdentityReader"/>; null: that one only.</param>
    public PdfEnvelopeValidator(PdfSignatureValidator validator, IEnumerable<ISignerIdentityReader>? identityReaders = null)
    {
        ArgumentNullException.ThrowIfNull(validator);
        _validator = validator;
        _readers = [.. identityReaders ?? []];
    }

    /// <summary>Validates the envelope of a document.</summary>
    /// <param name="pdf">The document.</param>
    /// <param name="cancellationToken">Cancels the validation.</param>
    /// <returns>The report.</returns>
    /// <exception cref="SigningException">The document holds no envelope (<see cref="SigningErrorReason.EnvelopeFieldNotFound"/>).</exception>
    public async Task<PdfEnvelopeReport> ValidateAsync(ReadOnlyMemory<byte> pdf, CancellationToken cancellationToken = default)
    {
        var envelope = PdfEnvelopeReader.Read(pdf, _readers)
            ?? throw new SigningException("The PDF holds no signature envelope.", SigningErrorReason.EnvelopeFieldNotFound);
        byte[] bytes = pdf.ToArray();
        IReadOnlyList<SignatureValidationResult> results;
        PdfInspectionResult inspection;
        using (var stream = new MemoryStream(bytes, writable: false))
        {
            results = await _validator.ValidateAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
        }

        using (var stream = new MemoryStream(bytes, writable: false))
        {
            inspection = await PdfSignatureInspector.InspectAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
        }

        var readers = _readers.Append(DefaultSignerIdentityReader.Instance).Distinct().ToList();
        bool sequential = envelope.Manifest?.Order == EnvelopeOrder.Sequential;
        var reports = new List<EnvelopeSignatureReport>();
        var fields = envelope.Fields.Where(f => f.Signer is not null).ToList();
        for (int i = 0; i < fields.Count; i++)
        {
            var field = fields[i];
            var signer = field.Signer!;
            if (!field.IsSigned)
            {
                reports.Add(new EnvelopeSignatureReport { Field = field.Name, Signer = signer, InOrder = true });
                continue;
            }

            // The signature: in the field, or, for a signer who signs outside it, in the field their tool made.
            string at = field.SignatureField ?? field.Name;
            var validation = results.FirstOrDefault(r => r.FieldName == at && !r.IsDocumentTimestamp);
            var certificate = validation?.SignerCertificate ?? field.SignerCertificate;
            var identifiers = certificate is null
                ? []
                : signer.Identifiers.Select(id => PdfEnvelope.Compare(id, certificate, readers)).ToList();
            var info = inspection.Signatures.FirstOrDefault(s => s.FieldName == at);
            var reached = info is null ? null : Baseline(ConformanceDetector.DetectStructure(info, inspection.Document, inspection.Signatures));
            var problems = LevelProblems(signer.Level, reached, info);

            // In order: signed after every field before it.
            bool inOrder = !sequential || fields.Take(i).All(f => f.IsSigned && f.SignatureOrder < field.SignatureOrder);
            reports.Add(new EnvelopeSignatureReport
            {
                Field = field.Name,
                Signer = signer,
                IsSigned = true,
                Validation = validation,
                Identifiers = identifiers,
                SignerMatches = certificate is not null && identifiers.All(c => c.Match == EnvelopeIdentifierMatch.Matched),
                ReachedLevel = reached,
                LevelMet = problems.Count == 0,
                LevelProblems = problems,
                InOrder = inOrder,
            });
        }

        return new PdfEnvelopeReport { Envelope = envelope, Signatures = reports };
    }

    private static AdesBaselineLevel? Baseline(PAdESConformanceLevel level) => level switch
    {
        PAdESConformanceLevel.BaselineB => AdesBaselineLevel.Basic,
        PAdESConformanceLevel.BaselineT => AdesBaselineLevel.Timestamped,
        PAdESConformanceLevel.BaselineLT => AdesBaselineLevel.LongTerm,
        PAdESConformanceLevel.BaselineLTA => AdesBaselineLevel.Archive,
        _ => null,
    };

    private static List<string> LevelProblems(EnvelopeLevel level, AdesBaselineLevel? reached, SignatureFieldInfo? info)
    {
        var problems = new List<string>();
        bool anything = level.Baseline == AdesBaselineLevel.Basic && !level.Timestamp && level.SubFilters.Count == 0 && level.PolicyOids.Count == 0;
        if (anything)
        {
            return problems;
        }

        if (reached is null || reached < level.Baseline)
        {
            problems.Add($"The signature reaches {(reached is { } r ? EnvelopeManifestJson.BaselineText(r) : "less than B-B")}; level {level.Id} needs {EnvelopeManifestJson.BaselineText(level.Baseline)}.");
        }

        if (level.Timestamp && (reached is null || reached < AdesBaselineLevel.Timestamped))
        {
            problems.Add($"Level {level.Id} needs a signature time-stamp.");
        }

        if (level.SubFilters.Count > 0 && (info?.SubFilter is not { } subFilter || !level.SubFilters.Contains(subFilter, StringComparer.Ordinal)))
        {
            problems.Add($"Level {level.Id} needs the SubFilter {string.Join(" or ", level.SubFilters)}; the signature has {info?.SubFilter ?? "none"}.");
        }

        if (level.PolicyOids.Count > 0 && (info?.SignaturePolicyOid is not { } policy || !level.PolicyOids.Contains(policy, StringComparer.Ordinal)))
        {
            problems.Add($"Level {level.Id} needs the signature policy {string.Join(" or ", level.PolicyOids)}; the signature has {info?.SignaturePolicyOid ?? "none"}.");
        }

        return problems;
    }
}

internal sealed class EnvelopeReportDto
{
    public string? Id { get; set; }

    public string? Status { get; set; }

    public bool IsComplete { get; set; }

    public bool OrderRespected { get; set; }

    public bool ManifestUnchanged { get; set; }

    public List<string>? MissingFields { get; set; }

    public List<string>? Problems { get; set; }

    public List<EnvelopeSignatureReportDto>? Signatures { get; set; }
}

internal sealed class EnvelopeSignatureReportDto
{
    public string? Field { get; set; }

    public string? Signer { get; set; }

    public bool IsSigned { get; set; }

    public string? Indication { get; set; }

    public string? SubIndication { get; set; }

    public string? SignerCertificate { get; set; }

    public DateTimeOffset? SigningTime { get; set; }

    public bool SignerMatches { get; set; }

    public List<EnvelopeIdentifierReportDto>? Identifiers { get; set; }

    public string? Level { get; set; }

    public string? ReachedLevel { get; set; }

    public bool LevelMet { get; set; }

    public List<string>? LevelProblems { get; set; }

    public bool InOrder { get; set; }

    public bool IsComplete { get; set; }
}

internal sealed class EnvelopeIdentifierReportDto
{
    public string? Type { get; set; }

    public string? Value { get; set; }

    public string? Match { get; set; }
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    WriteIndented = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(EnvelopeReportDto))]
internal sealed partial class EnvelopeReportJsonContext : JsonSerializerContext;
