using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Validation;
using SimpleSign.Peru.Iofe.Accredited.Internal;

namespace SimpleSign.Peru.Iofe.Accredited;

/// <summary>What an <see cref="IofeVerificationAgent"/> needs.</summary>
public sealed record IofeVerificationAgentOptions
{
    /// <summary>Where each verification is recorded (guide Req. 24), e.g. a <see cref="JsonLinesVerificationAuditSink"/>.</summary>
    public required IVerificationAuditSink Audit { get; init; }

    /// <summary>How the notice of a rejected document reaches its sender (guide section 4.3).</summary>
    public required IIofeSenderNotifier Notifier { get; init; }

    /// <summary>Whom to trust. Default: INDECOPI's trusted list.</summary>
    public IofeTrust Trust { get; init; } = IofeTrust.IndecopiList();

    /// <summary>A contingency under a procedure INDECOPI approved; null (the default) when there is none.</summary>
    public IofeContingency? Contingency { get; init; }

    /// <summary>The HTTP client of the revocation checks; null for the default.</summary>
    public IHttpClientProvider? HttpClientProvider { get; init; }

    /// <summary>The clock verifications are dated with and a contingency's validity is read on. Default: the system's.</summary>
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;
}

/// <summary>
/// Verification by an automated agent (INDECOPI's guide, section 4.3, Req. 21 to 30): a system that receives signed
/// documents and checks, without an operator, the certificate of every signature in each — trusted, not revoked (CRL
/// or OCSP), not expired at the time of signing, with nonRepudiation, with current algorithms. A document with any
/// signature that is not valid is rejected and a notice goes to its sender; every verification is recorded. Nothing
/// here lets the caller skip a check; the one exception the guide allows is a declared <see cref="IofeContingency"/>.
/// </summary>
/// <example>
/// <code>
/// await using var verifier = await IofeVerificationAgent.CreateAsync(new IofeVerificationAgentOptions
/// {
///     Audit = new JsonLinesVerificationAuditSink("/var/log/firma/verificacion.jsonl"),
///     Notifier = notifier,
/// });
/// IofeVerification result = await verifier.VerifyAsync(received, new IofeSender("20123456789", "mesa@entidad.pe"));
/// if (!result.Accepted) { /* result.Notice went to the sender */ }
/// </code>
/// </example>
public sealed class IofeVerificationAgent : IAsyncDisposable
{
    private readonly TrustProfile _profile;
    private readonly IAsyncDisposable? _ownedTrust;
    private readonly IofeVerificationAgentOptions _options;

    private IofeVerificationAgent(TrustProfile profile, IAsyncDisposable? ownedTrust, IofeVerificationAgentOptions options)
    {
        _profile = profile;
        _ownedTrust = ownedTrust;
        _options = options;
        Viewer = new IofeViewer(profile, options.HttpClientProvider);
    }

    /// <summary>The viewer for the documents received (Req. 28).</summary>
    public IofeViewer Viewer { get; }

    /// <summary>Loads the trust and creates the agent.</summary>
    /// <param name="options">The options.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The agent.</returns>
    /// <exception cref="IofeAccreditationException">The options carry no audit sink or no notifier.</exception>
    public static async Task<IofeVerificationAgent> CreateAsync(IofeVerificationAgentOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.Audit is null)
        {
            throw new IofeAccreditationException(
                "Un agente de verificación no opera sin registro de auditoría (Audit).", IofeRefusal.AuditMissing);
        }

        if (options.Notifier is null)
        {
            throw new IofeAccreditationException(
                "Se requiere el medio para devolver el comunicado al emisor (Notifier).", IofeRefusal.OptionsIncomplete);
        }

        var (profile, owned) = await options.Trust
            .ResolveAsync(IofePolicies.AgentSigning, IofePolicies.AgentValidation, cancellationToken).ConfigureAwait(false);
        return new IofeVerificationAgent(profile, owned, options);
    }

    /// <summary>
    /// Verifies every signature of a document received. When any is not valid — or the document has none or cannot be
    /// read — the document is rejected, the notice is handed to the notifier and both are recorded.
    /// </summary>
    /// <param name="document">The document received (PDF, CMS or XML).</param>
    /// <param name="sender">Who sent it.</param>
    /// <param name="request">The detached content and the reference, when there are any.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The result, with the report and, for a rejected document, the notice.</returns>
    /// <exception cref="IofeAccreditationException">The contingency has expired, or the notice could not be delivered.</exception>
    public async Task<IofeVerification> VerifyAsync(
        byte[] document, IofeSender sender, IofeVerificationRequest? request = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(sender);
        request ??= new IofeVerificationRequest();

        var time = _options.TimeProvider.GetUtcNow();
        string sha256 = Convert.ToHexString(SHA256.HashData(document));
        var contingency = _options.Contingency;
        if (contingency is not null && !contingency.IsInForce(time))
        {
            throw new IofeAccreditationException(
                $"La contingencia '{contingency.ProcedureReference}' no está vigente ({contingency.From:u} a {contingency.Until:u}).",
                IofeRefusal.ContingencyExpired);
        }

        var profile = _profile;
        var outcome = await IofeValidation.ValidateAsync(
            document, request.DetachedContent, profile, _options.HttpClientProvider,
            checkRevocation: true, request.Reference, cancellationToken).ConfigureAwait(false);
        if (contingency is not null && OnlyRevocationStatusIsMissing(outcome))
        {
            // The contingency: the status was asked for and could not be obtained. A certificate known to be revoked
            // never gets here.
            outcome = await IofeValidation.ValidateAsync(
                document, request.DetachedContent, profile, _options.HttpClientProvider,
                checkRevocation: false, request.Reference, cancellationToken).ConfigureAwait(false);
        }

        var reasons = Reasons(outcome);
        bool accepted = reasons.Count == 0;
        var notice = accepted ? null : Notice(sender, sha256, time, reasons, request.Reference, profile.ValidationPolicy.Name);
        var auditEvent = new IofeVerificationAuditEvent
        {
            Time = time,
            Format = outcome.Format,
            DocumentSha256 = sha256,
            SenderId = sender.Id,
            Reference = request.Reference,
            Accepted = accepted,
            Indications = [.. outcome.Signatures.Select(s => s.Indication.ToString())],
            Reasons = reasons,
            PolicyName = profile.ValidationPolicy.Name,
            PolicyDigest = profile.ValidationPolicy.Digest,
            Contingency = contingency?.ProcedureReference,
        };

        if (notice is not null)
        {
            try
            {
                await _options.Notifier.NotifyAsync(notice, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                await _options.Audit.RecordAsync(auditEvent with { NoticeDelivered = false }, cancellationToken).ConfigureAwait(false);
                throw new IofeAccreditationException(
                    $"No se pudo entregar el comunicado de rechazo al emisor '{sender.Id}': {ex.Message}", IofeRefusal.NoticeNotDelivered, ex);
            }

            auditEvent = auditEvent with { NoticeDelivered = true };
        }

        await _options.Audit.RecordAsync(auditEvent, cancellationToken).ConfigureAwait(false);
        return new IofeVerification
        {
            Accepted = accepted,
            Format = outcome.Format,
            DocumentSha256 = sha256,
            Time = time,
            Signatures = outcome.Signatures,
            Reasons = reasons,
            Notice = notice,
            ReportHtml = ValidationReports.ToHtml(outcome.Signatures, "es", time),
            EtsiReportXml = outcome.Signatures.Count == 0 ? string.Empty : ValidationReports.ToEtsiXml(outcome.Signatures, validationTime: time),
        };
    }

    /// <summary>Releases the trusted list this agent loaded.</summary>
    /// <returns>A task that completes when it is released.</returns>
    public ValueTask DisposeAsync() => _ownedTrust?.DisposeAsync() ?? ValueTask.CompletedTask;

    /// <summary>
    /// Whether the document is held back by nothing but a revocation status that could not be obtained: it could be
    /// read, and in every signature that is not valid the only checks that did not pass are those named
    /// <c>RevocationDataAvailable</c> and <c>AcceptableRevocationDataFound</c>. A revoked certificate fails
    /// <c>NotRevoked</c> and never qualifies; a signature whose checks are not reported does not qualify either.
    /// </summary>
    private static bool OnlyRevocationStatusIsMissing(IofeValidationOutcome outcome)
    {
        var notValid = outcome.Signatures.Where(s => s.Indication != SignatureIndication.Valid).ToList();
        return outcome.DocumentErrors.Count == 0 && notValid.Count > 0 && notValid.TrueForAll(HeldBackByTheMissingStatusOnly);
    }

    private static bool HeldBackByTheMissingStatusOnly(SignatureReportEntry signature)
    {
        var decisive = signature.Constraints
            .Where(c => c.Status is ConstraintStatus.Failed or ConstraintStatus.Indeterminate)
            .ToList();
        return signature.Indication == SignatureIndication.Indeterminate
            && decisive.Count > 0
            && decisive.TrueForAll(c =>
                c.Id.EndsWith("/RevocationDataAvailable", StringComparison.Ordinal)
                || c.Id.EndsWith("/AcceptableRevocationDataFound", StringComparison.Ordinal));
    }

    private static List<string> Reasons(IofeValidationOutcome outcome)
    {
        List<string> reasons = [.. outcome.DocumentErrors];
        if (outcome.Signatures.Count == 0 && outcome.DocumentErrors.Count == 0)
        {
            reasons.Add("El documento no contiene firmas digitales.");
        }

        for (int i = 0; i < outcome.Signatures.Count; i++)
        {
            var signature = outcome.Signatures[i];
            if (signature.Indication == SignatureIndication.Valid)
            {
                continue;
            }

            string signer = signature.SignerCertificate?.Subject ?? "firmante desconocido";
            string indication = signature.Indication == SignatureIndication.Invalid ? "NO VÁLIDA" : "INDETERMINADA";
            string detail = signature.Errors.Count > 0
                ? string.Join("; ", signature.Errors)
                : signature.SubIndication?.ToString() ?? "sin detalle";
            reasons.Add(string.Create(CultureInfo.InvariantCulture, $"Firma {i + 1} ({signer}): {indication} — {detail}"));
        }

        return reasons;
    }

    private static IofeRejectionNotice Notice(
        IofeSender sender, string sha256, DateTimeOffset time, List<string> reasons, string? reference, string? policyName)
    {
        var text = new StringBuilder()
            .AppendLine("COMUNICADO DE RECHAZO DE DOCUMENTO FIRMADO DIGITALMENTE")
            .AppendLine()
            .AppendLine(CultureInfo.InvariantCulture, $"Emisor: {sender.Id}");
        if (reference is not null)
        {
            text.AppendLine(CultureInfo.InvariantCulture, $"Referencia: {reference}");
        }

        text.AppendLine(CultureInfo.InvariantCulture, $"Documento (SHA-256): {sha256}")
            .AppendLine(CultureInfo.InvariantCulture, $"Fecha y hora de la verificación (UTC): {time.UtcDateTime:yyyy-MM-dd HH:mm:ss}")
            .AppendLine(CultureInfo.InvariantCulture, $"Política de validación: {policyName}")
            .AppendLine()
            .AppendLine("El documento no fue aceptado por los siguientes motivos:");
        foreach (string reason in reasons)
        {
            text.AppendLine(CultureInfo.InvariantCulture, $" - {reason}");
        }

        text.AppendLine()
            .AppendLine("La verificación se realizó de manera automatizada, conforme a la Guía de Acreditación de Aplicaciones de Software del INDECOPI (IOFE).");
        return new IofeRejectionNotice(sender, sha256, time, reasons, text.ToString(), reference);
    }
}
