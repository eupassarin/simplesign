using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.Peru.Iofe.Accredited.Internal;
using SimpleSign.Signers.Cloud;
using SimpleSign.Signers.Pkcs11;

namespace SimpleSign.Peru.Iofe.Accredited;

/// <summary>What an <see cref="IofeSigningAgent"/> needs.</summary>
public sealed record IofeSigningAgentOptions
{
    /// <summary>
    /// The organization's cryptographic module (HSM): its PKCS#11 driver, the key and the PIN. The key is given either
    /// this way or as a <see cref="RemoteService"/>, one of the two: a certificate file (PKCS#12) or a key in memory
    /// cannot be used (guide Req. 15).
    /// </summary>
    public Pkcs11SignerOptions? Module { get; init; }

    /// <summary>
    /// The module the operator declares, with its FIPS 140-2 or Common Criteria EAL 4+ certificate (guide Req. 15: for
    /// an automated agent the module is part of what is accredited). Another token is refused. Required with
    /// <see cref="Module"/>.
    /// </summary>
    public IofeModuleDeclaration? ModuleDeclaration { get; init; }

    /// <summary>
    /// A remote signing service that keeps the organization's key in its own module, instead of <see cref="Module"/>:
    /// the agent sends the hash and receives the signature.
    /// </summary>
    public IofeRemoteService? RemoteService { get; init; }

    /// <summary>
    /// The remote service the operator declares, with its accreditation. Another service is refused, before the PIN
    /// or the service token is sent to it. Required with <see cref="RemoteService"/>.
    /// </summary>
    public IofeRemoteServiceDeclaration? RemoteServiceDeclaration { get; init; }

    /// <summary>Where each signature made or refused is recorded (guide Req. 14), e.g. a <see cref="JsonLinesAuditSink"/>.</summary>
    public required ISignatureAuditSink Audit { get; init; }

    /// <summary>
    /// The kinds of transaction this agent signs for. A signature asked for any other kind is refused and recorded
    /// (guide Req. 14: no signatures outside the transaction defined for unattended signing).
    /// </summary>
    public required IReadOnlyCollection<string> Transactions { get; init; }

    /// <summary>Whom to trust. Default: INDECOPI's trusted list.</summary>
    public IofeTrust Trust { get; init; } = IofeTrust.IndecopiList();

    /// <summary>
    /// The time-stamp authority (guide section 4.4); with one, signatures are made at B-LT and every token is checked
    /// before the signature is returned: it is this authority's, its signature verifies, and the authority's
    /// certificate is trusted, not expired and not revoked.
    /// </summary>
    public IofeTimestampAuthority? Timestamp { get; init; }

    /// <summary>A contingency under a procedure INDECOPI approved; null (the default) when there is none.</summary>
    public IofeContingency? Contingency { get; init; }

    /// <summary>The HTTP client of the revocation checks and of the time-stamp requests; null for the default.</summary>
    public IHttpClientProvider? HttpClientProvider { get; init; }

    /// <summary>The clock a contingency's validity is read on. Default: the system's.</summary>
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;
}

/// <summary>
/// Signing by an automated agent (INDECOPI's guide, section 4.2, Req. 11 to 20): unattended signatures of a legal
/// person, with one key kept in the organization's cryptographic module or in a remote signing service the operator
/// declares. Before each signature the certificate and
/// its chain are checked — trusted, not revoked (CRL or OCSP), not expired, with nonRepudiation, with current
/// algorithms — every signature made or refused is recorded, and only the declared kinds of transaction are signed.
/// Nothing here lets the caller skip a check; the one exception the guide allows is a declared
/// <see cref="IofeContingency"/>.
/// </summary>
/// <example>
/// <code>
/// await using var agent = await IofeSigningAgent.OpenAsync(new IofeSigningAgentOptions
/// {
///     Module = new Pkcs11SignerOptions { LibraryPath = hsmDriver, TokenLabel = "firma", KeyLabel = "sello-2026", Pin = pin },
///     ModuleDeclaration = new IofeModuleDeclaration("Thales", "Luna K7", "FIPS 140-2 Level 3", "4090"),
///     Audit = new JsonLinesAuditSink("/var/log/firma/auditoria.jsonl"),
///     Transactions = ["factura", "constancia"],
///     Timestamp = new IofeTimestampAuthority(new Uri(tsaUrl), tsaCertificate),
/// });
/// IofeSignedDocument signed = await agent.SignPdfAsync(pdf, new IofeTransaction("factura", "F001-123"));
///
/// // The same agent with the key in a remote signing service (CSC v2) instead of the organization's module:
/// //   RemoteService = new IofeRemoteService
/// //   {
/// //       Service = new CscClientOptions { BaseUri = serviceUri, ClientId = clientId, ClientSecret = clientSecret },
/// //       CredentialId = "sello-2026", Pin = pin,
/// //   },
/// //   RemoteServiceDeclaration = new IofeRemoteServiceDeclaration("Proveedor S.A.", "Firma Remota", "PSVA acreditado (firma remota)", "Res. 000-2025/DGI"),
/// </code>
/// </example>
public sealed class IofeSigningAgent : IAsyncDisposable
{
    private readonly IofeSigningCore _core;
    private readonly HashSet<string> _transactions;

    private IofeSigningAgent(IofeSigningCore core, HashSet<string> transactions)
    {
        _core = core;
        _transactions = transactions;
    }

    /// <summary>
    /// The module in use, how it protects the key, and what the operator declared about it; null when the key is in a
    /// remote service.
    /// </summary>
    public IofeModuleInfo? Module => _core.Module;

    /// <summary>The remote signing service in use and what the operator declared about it; null when the key is in a module.</summary>
    public IofeRemoteServiceInfo? RemoteService => _core.RemoteService;

    /// <summary>The subject of the signing certificate.</summary>
    public string SignerSubject => _core.SignerSubject;

    /// <summary>The viewer for the signed documents (Req. 18).</summary>
    public IofeViewer Viewer => _core.Viewer;

    /// <summary>
    /// Loads the trust and opens the key: the module, checked to be the declared one and to keep its key inside; or
    /// the credential of the remote service, checked to be the declared service.
    /// </summary>
    /// <param name="options">The options.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The agent. Dispose it to log out of the module.</returns>
    /// <exception cref="IofeAccreditationException">
    /// The options carry no audit sink, no transactions, no key source or two of them, or no declaration of it; the key
    /// is not confined to the module; the module or the remote service is not the declared one; or the credential of
    /// the remote service needs a person to authorize it.
    /// </exception>
    /// <exception cref="Pkcs11Exception">The module cannot be opened (driver, PIN, key selection).</exception>
    /// <exception cref="CloudSigningException">The remote service refused the agent, or its credential cannot be read or is disabled.</exception>
    public static async Task<IofeSigningAgent> OpenAsync(IofeSigningAgentOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.Audit is null)
        {
            throw new IofeAccreditationException(
                "Un agente automatizado no firma sin registro de auditoría (Audit).", IofeRefusal.AuditMissing);
        }

        bool module = options.Module is not null || options.ModuleDeclaration is not null;
        bool remote = options.RemoteService is not null || options.RemoteServiceDeclaration is not null;
        if (module == remote)
        {
            throw new IofeAccreditationException(
                "Se requiere una fuente de la clave, y solo una: el módulo criptográfico (Module) o el servicio de firma remota (RemoteService).",
                IofeRefusal.OptionsIncomplete);
        }

        if (module && (options.Module is null || options.ModuleDeclaration is null))
        {
            throw new IofeAccreditationException(
                "Se requieren el módulo criptográfico (Module) y su declaración (ModuleDeclaration).", IofeRefusal.OptionsIncomplete);
        }

        if (remote && (options.RemoteService is null || options.RemoteServiceDeclaration is null))
        {
            throw new IofeAccreditationException(
                "Se requieren el servicio de firma remota (RemoteService) y su declaración (RemoteServiceDeclaration).",
                IofeRefusal.OptionsIncomplete);
        }

        var transactions = new HashSet<string>(
            (options.Transactions ?? []).Where(t => !string.IsNullOrWhiteSpace(t)), StringComparer.Ordinal);
        if (transactions.Count == 0)
        {
            throw new IofeAccreditationException(
                "Se requiere al menos un tipo de transacción (Transactions).", IofeRefusal.OptionsIncomplete);
        }

        var core = remote
            ? await IofeSigningCore.OpenRemoteAsync(
                options.RemoteService!,
                options.RemoteServiceDeclaration!,
                options.Trust,
                IofePolicies.AgentSigning,
                IofePolicies.AgentValidation,
                options.Audit,
                options.Timestamp?.ToOptions(),
                options.Contingency,
                options.HttpClientProvider,
                options.TimeProvider,
                cancellationToken).ConfigureAwait(false)
            : await IofeSigningCore.OpenModuleAsync(
                options.Module!,
                options.ModuleDeclaration!,
                options.Trust,
                IofePolicies.AgentSigning,
                IofePolicies.AgentValidation,
                options.Audit,
                options.Timestamp?.ToOptions(),
                options.Contingency,
                options.HttpClientProvider,
                options.TimeProvider,
                cancellationToken).ConfigureAwait(false);
        return new IofeSigningAgent(core, transactions);
    }

    /// <summary>Signs a PDF (PAdES) for a transaction.</summary>
    /// <param name="pdf">The PDF.</param>
    /// <param name="transaction">The transaction the signature is for.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The signed PDF.</returns>
    /// <exception cref="IofeAccreditationException">The kind of transaction is not one of the agent's, or the contingency has expired.</exception>
    /// <exception cref="SigningException">A check of the signing policy refused the certificate; see its <c>Reason</c>.</exception>
    public async Task<IofeSignedDocument> SignPdfAsync(byte[] pdf, IofeTransaction transaction, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pdf);
        await RequireAllowedAsync(transaction, cancellationToken).ConfigureAwait(false);
        return await _core.SignPdfAsync(pdf, transaction.OperationId, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Signs data as a CMS signature (CAdES) for a transaction.</summary>
    /// <param name="data">The data.</param>
    /// <param name="transaction">The transaction the signature is for.</param>
    /// <param name="detached">True to leave the data out of the signature; false (the default) to carry it inside.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The CMS signature.</returns>
    /// <exception cref="IofeAccreditationException">The kind of transaction is not one of the agent's, or the contingency has expired.</exception>
    /// <exception cref="SigningException">A check of the signing policy refused the certificate; see its <c>Reason</c>.</exception>
    public async Task<IofeSignedDocument> SignCmsAsync(
        byte[] data, IofeTransaction transaction, bool detached = false, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(data);
        await RequireAllowedAsync(transaction, cancellationToken).ConfigureAwait(false);
        return await _core.SignCmsAsync(data, detached, transaction.OperationId, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Signs an XML document with an enveloped signature (XAdES) for a transaction.</summary>
    /// <param name="xml">The XML document.</param>
    /// <param name="transaction">The transaction the signature is for.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The signed XML.</returns>
    /// <exception cref="IofeAccreditationException">The kind of transaction is not one of the agent's, or the contingency has expired.</exception>
    /// <exception cref="SigningException">A check of the signing policy refused the certificate; see its <c>Reason</c>.</exception>
    public async Task<IofeSignedDocument> SignXmlAsync(byte[] xml, IofeTransaction transaction, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(xml);
        await RequireAllowedAsync(transaction, cancellationToken).ConfigureAwait(false);
        return await _core.SignXmlAsync(xml, transaction.OperationId, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Logs out of the module (or lets go of the remote credential) and releases the trusted list this agent loaded.</summary>
    /// <returns>A task that completes when both are released.</returns>
    public ValueTask DisposeAsync() => _core.DisposeAsync();

    private async Task RequireAllowedAsync(IofeTransaction transaction, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        if (!_transactions.Contains(transaction.Type))
        {
            await _core.RefuseAsync(
                IofeRefusal.TransactionNotAllowed,
                $"El tipo de transacción '{transaction.Type}' no está entre los definidos para este agente.",
                transaction.OperationId,
                cancellationToken).ConfigureAwait(false);
        }
    }
}
