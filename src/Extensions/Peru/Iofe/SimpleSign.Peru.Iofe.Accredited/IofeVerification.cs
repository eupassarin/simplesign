using SimpleSign.Core.Validation;

namespace SimpleSign.Peru.Iofe.Accredited;

/// <summary>Who sent a signed document to an <see cref="IofeVerificationAgent"/>.</summary>
/// <param name="Id">The sender, as the receiving system identifies it (e.g. a RUC).</param>
/// <param name="Contact">Where a notice reaches the sender (an address, an endpoint); the notifier decides how to use it.</param>
public sealed record IofeSender(string Id, string? Contact = null);

/// <summary>What accompanies a document given to <see cref="IofeVerificationAgent.VerifyAsync"/>.</summary>
public sealed record IofeVerificationRequest
{
    /// <summary>The signed content of a detached signature (CMS or XML).</summary>
    public byte[]? DetachedContent { get; init; }

    /// <summary>The reference of this reception in the receiving system; written to the audit record and the notice.</summary>
    public string? Reference { get; init; }
}

/// <summary>
/// The notice a verification agent returns to the sender of a document it rejected (guide section 4.3: "en caso de no
/// ser válido alguno de los certificados, la aplicación deberá devolver un comunicado al emisor").
/// </summary>
/// <param name="Sender">Who sent the document.</param>
/// <param name="DocumentSha256">The SHA-256 of the document received, upper-case hex.</param>
/// <param name="Time">When it was verified.</param>
/// <param name="Reasons">Why it was rejected, one line per finding.</param>
/// <param name="Text">The notice, in Spanish, ready to send.</param>
/// <param name="Reference">The reference of the reception, when given.</param>
public sealed record IofeRejectionNotice(
    IofeSender Sender,
    string DocumentSha256,
    DateTimeOffset Time,
    IReadOnlyList<string> Reasons,
    string Text,
    string? Reference);

/// <summary>Delivers the notice of a rejected document to its sender: an e-mail, a reply on the channel it came by.</summary>
public interface IIofeSenderNotifier
{
    /// <summary>Delivers <paramref name="notice"/>. An exception here fails the verification, and is recorded.</summary>
    /// <param name="notice">The notice.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that completes when the notice is on its way.</returns>
    ValueTask NotifyAsync(IofeRejectionNotice notice, CancellationToken cancellationToken);
}

/// <summary>What an <see cref="IofeVerificationAgent"/> found in a document.</summary>
public sealed record IofeVerification
{
    /// <summary>Whether the document is accepted: it has signatures and every one of them is valid under the IOFE policy.</summary>
    public required bool Accepted { get; init; }

    /// <summary>The format of the document.</summary>
    public required IofeDocumentFormat Format { get; init; }

    /// <summary>The SHA-256 of the document, upper-case hex.</summary>
    public required string DocumentSha256 { get; init; }

    /// <summary>When it was verified.</summary>
    public required DateTimeOffset Time { get; init; }

    /// <summary>Each signature of the document with its result.</summary>
    public IReadOnlyList<SignatureReportEntry> Signatures { get; init; } = [];

    /// <summary>Why the document was rejected; empty when it was accepted.</summary>
    public IReadOnlyList<string> Reasons { get; init; } = [];

    /// <summary>The notice handed to the notifier; null when the document was accepted.</summary>
    public IofeRejectionNotice? Notice { get; init; }

    /// <summary>The validation report as a page in Spanish (the viewer of Req. 28).</summary>
    public required string ReportHtml { get; init; }

    /// <summary>The validation report of ETSI TS 119 102-2 (XML); empty when the document has no signature to report.</summary>
    public required string EtsiReportXml { get; init; }
}
