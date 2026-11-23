using System.Globalization;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES.Signing;

namespace SimpleSign.PAdES.Envelope;

/// <summary>
/// Prepares an envelope in a PDF (ADR 0033): one signature field per signer, with seed values and a lock, and the
/// manifest as an associated file, written in one incremental update before any signature. Each call returns a new
/// builder.
/// </summary>
/// <example>
/// <code>
/// byte[] prepared = await PdfEnvelope.Prepare(pdf)
///     .WithOrder(EnvelopeOrder.Sequential)
///     .AddSigner(new EnvelopeSigner
///     {
///         Name = "Maria Silva",
///         Identifiers = [new EnvelopeIdentifier("CPF", "12345678909")],
///         Role = "Diretora",
///         Placement = new EnvelopePlacement(1, 72, 72, 200, 50),
///     })
///     .PrepareAsync();
/// </code>
/// </example>
public sealed class PdfEnvelopeBuilder
{
    private readonly ReadOnlyMemory<byte> _pdf;
    private readonly State _state;

    internal PdfEnvelopeBuilder(ReadOnlyMemory<byte> pdf)
        : this(pdf, new State())
    {
    }

    private PdfEnvelopeBuilder(ReadOnlyMemory<byte> pdf, State state)
    {
        _pdf = pdf;
        _state = state;
    }

    /// <summary>The order the signers sign in; sequential by default.</summary>
    /// <param name="order">The order.</param>
    public PdfEnvelopeBuilder WithOrder(EnvelopeOrder order) => new(_pdf, _state with { Order = order });

    /// <summary>Adds a signer, after those added before: their field is <c>SimpleSign_</c> and their place in the list, from 1.</summary>
    /// <param name="signer">The signer.</param>
    /// <exception cref="ArgumentException">The signer has no name, a placement of no size, or an identifier without a type or value.</exception>
    public PdfEnvelopeBuilder AddSigner(EnvelopeSigner signer)
    {
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentException.ThrowIfNullOrWhiteSpace(signer.Name, nameof(signer));
        ArgumentNullException.ThrowIfNull(signer.Placement, nameof(signer));
        ArgumentNullException.ThrowIfNull(signer.Level, nameof(signer));
        if (!(signer.Placement.Width > 0 && signer.Placement.Height > 0) || !float.IsFinite(signer.Placement.X) || !float.IsFinite(signer.Placement.Y))
        {
            throw new ArgumentException($"The placement of '{signer.Name}' needs a finite position and a width and height above zero.", nameof(signer));
        }

        if (signer.Identifiers.Any(i => string.IsNullOrWhiteSpace(i.Type) || string.IsNullOrWhiteSpace(i.Value)))
        {
            throw new ArgumentException($"An identifier of '{signer.Name}' has no type or no value.", nameof(signer));
        }

        return new(_pdf, _state with { Signers = [.. _state.Signers, signer] });
    }

    /// <summary>
    /// The time-stamp server written in the seed values of the fields whose level needs a signature time-stamp
    /// (<c>/SV /TimeStamp</c>, required), so that a reader that follows seed values uses it.
    /// </summary>
    /// <param name="url">The server's URL.</param>
    public PdfEnvelopeBuilder WithTimestampUrl(Uri url)
    {
        ArgumentNullException.ThrowIfNull(url);
        return new(_pdf, _state with { TimestampUrl = url });
    }

    /// <summary>
    /// Asks the first signer to certify the document (DocMDP) with this level, in the first field's seed values
    /// (<c>/SV /MDP</c>). <see cref="CertificationLevel.FormFilling"/> lets the later signatures in.
    /// </summary>
    /// <param name="level">The certification level; <see cref="CertificationLevel.NoChanges"/> only for one signer.</param>
    public PdfEnvelopeBuilder WithCertification(CertificationLevel level) => new(_pdf, _state with { Certification = level });

    /// <summary>
    /// The last field of a sequential envelope locks the document once signed (<c>/Lock /P 1</c>, ISO 32000-2
    /// §12.7.5.5): no change after the last signature.
    /// </summary>
    public PdfEnvelopeBuilder WithDocumentLock() => new(_pdf, _state with { LockDocument = true });

    /// <summary>The envelope's id; a new GUID by default.</summary>
    /// <param name="id">The id.</param>
    public PdfEnvelopeBuilder WithId(string id)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        return new(_pdf, _state with { Id = id });
    }

    /// <summary>The clock the preparation date is read from; the system's by default.</summary>
    /// <param name="timeProvider">The clock.</param>
    public PdfEnvelopeBuilder WithTimeProvider(TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        return new(_pdf, _state with { TimeProvider = timeProvider });
    }

    /// <summary>The manifest the envelope will hold, as <see cref="PrepareAsync"/> writes it.</summary>
    /// <exception cref="InvalidOperationException">No signer was added.</exception>
    public EnvelopeManifest BuildManifest()
    {
        if (_state.Signers.Count == 0)
        {
            throw new InvalidOperationException("An envelope needs at least one signer.");
        }

        if (_state.Certification == CertificationLevel.NoChanges && _state.Signers.Count > 1)
        {
            throw new InvalidOperationException("A certification that allows no change (P1) would refuse every signature after the first one.");
        }

        var now = _state.TimeProvider.GetUtcNow();
        return new EnvelopeManifest
        {
            Id = _state.Id ?? Guid.NewGuid().ToString("D", CultureInfo.InvariantCulture),
            Order = _state.Order,
            PreparedAt = new DateTimeOffset(now.Year, now.Month, now.Day, now.Hour, now.Minute, now.Second, TimeSpan.Zero),
            Signers = [.. _state.Signers.Select((s, i) => new EnvelopeManifestSigner
            {
                Field = PdfEnvelopeWriter.FieldPrefix + (i + 1).ToString(CultureInfo.InvariantCulture),
                Name = s.Name,
                Role = s.Role,
                Email = s.Email,
                External = s.External,
                Identifiers = s.Identifiers,
                Level = s.Level,
            })],
        };
    }

    /// <summary>Writes the envelope.</summary>
    /// <param name="cancellationToken">Cancels the preparation.</param>
    /// <returns>The document with the envelope, its earlier bytes unchanged.</returns>
    /// <exception cref="InvalidOperationException">No signer was added, or the certification allows no change with more than one signer.</exception>
    /// <exception cref="SigningException">
    /// The document is encrypted (<see cref="SigningErrorReason.DocumentEncrypted"/>), or is signed, certified, PDF/A-1, or
    /// already holds an envelope (<see cref="SigningErrorReason.DocumentNotSignable"/>).
    /// </exception>
    /// <exception cref="ArgumentException">A placement is not on a page of the document.</exception>
    public Task<byte[]> PrepareAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var manifest = BuildManifest();
        return Task.FromResult(PdfEnvelopeWriter.Write(
            _pdf, manifest, new PdfEnvelopeLayout(_state.Signers, _state.TimestampUrl, _state.Certification, _state.LockDocument)));
    }

    private sealed record State
    {
        public EnvelopeOrder Order { get; init; }

        public IReadOnlyList<EnvelopeSigner> Signers { get; init; } = [];

        public Uri? TimestampUrl { get; init; }

        public CertificationLevel? Certification { get; init; }

        public bool LockDocument { get; init; }

        public string? Id { get; init; }

        public TimeProvider TimeProvider { get; init; } = TimeProvider.System;
    }
}
