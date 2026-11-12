using System.Diagnostics.CodeAnalysis;

namespace SimpleSign.XAdES;

/// <summary>
/// Entry point for two-phase XAdES signing, where the private key is held on another machine (a token or
/// smart card behind a browser or a local agent): the server prepares the signature and gets the bytes to
/// sign, the key signs them, and the server — the same process or another — completes the signature.
/// </summary>
/// <example>
/// <code>
/// // Phase 1 — server: run the signing policy and get the bytes to sign.
/// var prepared = await XadesDeferredSigner.Document(xml)
///     .WithCertificate(publicCertificate, chain)
///     .WithSessionIntegrityKey(sessionIntegrityKey)
///     .WithForm(XadesForm.Enveloped)
///     .WithLevel(AdesBaselineProfile.Timestamped(new TimestampOptions(tsaUri)))
///     .PrepareAsync();
/// // Keep prepared.SessionData on the server; send prepared.DataToSign to the signer.
///
/// // Phase 2 — server: complete with the raw signature.
/// byte[] signedXml = await XadesDeferredSigner.Resume(prepared.SessionData, sessionIntegrityKey)
///     .CompleteAsync(rawSignature);
/// </code>
/// </example>
[RequiresUnreferencedCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
[RequiresDynamicCode("XAdES uses System.Security.Cryptography.Xml which is not AOT-compatible.")]
public static class XadesDeferredSigner
{
    /// <summary>Creates a builder that prepares a two-phase XAdES signature of <paramref name="xmlData"/>.</summary>
    /// <param name="xmlData">The XML document bytes to sign. The array is copied.</param>
    /// <returns>A builder that needs <c>WithCertificate</c> and <c>WithSessionIntegrityKey</c> before <c>PrepareAsync</c>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="xmlData"/> is null.</exception>
    public static XadesDeferredSignerBuilder Document(byte[] xmlData)
    {
        ArgumentNullException.ThrowIfNull(xmlData);
        return new XadesDeferredSignerBuilder(new XadesSignerBuilder(xmlData, logger: null), session: null, sessionIntegrityKey: null);
    }

    /// <summary>
    /// Creates a builder that prepares in two phases the signature a one-call builder is configured for: its
    /// document (or the countersignature it was created for), its certificate and chain, and every option.
    /// The private key of the certificate, or the external signer, is not used: the key signs between the
    /// phases. Use it to configure a signature once and decide how it is signed at the end.
    /// </summary>
    /// <param name="builder">A builder from <see cref="XadesSigner"/>, configured.</param>
    /// <returns>A builder that needs <c>WithSessionIntegrityKey</c> before <c>PrepareAsync</c>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="builder"/> is null.</exception>
    public static XadesDeferredSignerBuilder From(XadesSignerBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return new XadesDeferredSignerBuilder(builder.ForDeferredPreparation(), session: null, sessionIntegrityKey: null);
    }

    /// <summary>
    /// Creates a builder that prepares a two-phase countersignature of a signature of an already signed document
    /// (ETSI EN 319 132-1 §5.2.7.2). The bytes to sign are the canonical SignedInfo of the countersignature.
    /// The builder accepts the B-B and B-T levels. See <see cref="XadesSigner.CounterSign"/>.
    /// </summary>
    /// <param name="signedXml">The signed XML document. The array is copied.</param>
    /// <param name="signatureId">The Id of the ds:Signature to countersign; null when the document has a single signature.</param>
    /// <returns>A builder that needs <c>WithCertificate</c> and <c>WithSessionIntegrityKey</c> before <c>PrepareAsync</c>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="signedXml"/> is null.</exception>
    public static XadesDeferredSignerBuilder CounterSign(byte[] signedXml, string? signatureId = null) =>
        From(XadesSigner.CounterSign(signedXml, signatureId));

    /// <summary>Resumes a session prepared by <see cref="XadesDeferredSignerBuilder.PrepareAsync(CancellationToken)"/>.</summary>
    /// <param name="sessionData">The session returned by phase one.</param>
    /// <param name="sessionIntegrityKey">The server-owned HMAC key given in phase one.</param>
    /// <returns>A builder that completes the session.</returns>
    /// <exception cref="ArgumentException">The data is not a XAdES deferred session, or the key has less than 32 bytes.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">The session was changed, or the key is not the one of phase one.</exception>
    public static XadesDeferredSignerBuilder Resume(byte[] sessionData, byte[] sessionIntegrityKey)
    {
        ArgumentNullException.ThrowIfNull(sessionData);
        ArgumentOutOfRangeException.ThrowIfZero(sessionData.Length);
        ArgumentNullException.ThrowIfNull(sessionIntegrityKey);
        XadesDeferredSession session = XadesDeferredSession.Read(sessionData, sessionIntegrityKey);
        return new XadesDeferredSignerBuilder(XadesSignerBuilder.ForDeferredCompletion(session), session, sessionIntegrityKey: null);
    }
}
