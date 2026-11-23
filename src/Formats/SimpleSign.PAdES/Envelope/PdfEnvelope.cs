namespace SimpleSign.PAdES.Envelope;

/// <summary>
/// A signature envelope inside a PDF (ADR 0033): several people sign the same document in turn, with no server; the
/// PDF itself says who signs, in which order, where, and at which level.
/// <list type="bullet">
/// <item><see cref="Prepare"/> writes the fields and the manifest, before any signature;</item>
/// <item><see cref="PdfEnvelopeReader"/> reads them back, with what is signed and who is next;</item>
/// <item><see cref="CheckSigner"/> tells, before the PIN is asked, whether a certificate may sign a field;</item>
/// <item><c>WithEnvelopeField</c> on <see cref="PadesSignerBuilder"/> and <see cref="DeferredSignerBuilder"/> signs a field;</item>
/// <item><see cref="PdfEnvelopeValidator"/> validates the whole envelope.</item>
/// </list>
/// </summary>
public static partial class PdfEnvelope
{
    /// <summary>Starts preparing an envelope in a document.</summary>
    /// <param name="pdf">The document, not signed yet.</param>
    public static PdfEnvelopeBuilder Prepare(ReadOnlyMemory<byte> pdf) => new(pdf);
}
