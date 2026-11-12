namespace SimpleSign.CAdES;

/// <summary>
/// Entry point for two-phase CAdES signing, where the private key is held on another machine (a token or
/// smart card behind a browser or a local agent): the server prepares the signature and gets the bytes to
/// sign, the key signs them, and the server — the same process or another — completes the signature.
/// </summary>
/// <example>
/// <code>
/// // Phase 1 — server: run the signing policy and get the bytes to sign.
/// var prepared = await CadesDeferredSigner.Document(data)
///     .WithCertificate(publicCertificate, chain)
///     .WithSessionIntegrityKey(sessionIntegrityKey)
///     .WithLevel(AdesBaselineProfile.Timestamped(new TimestampOptions(tsaUri)))
///     .PrepareAsync();
/// // Keep prepared.SessionData on the server; send prepared.DataToSign to the signer.
///
/// // Phase 2 — server: complete with the raw signature.
/// byte[] cms = await CadesDeferredSigner.Resume(prepared.SessionData, sessionIntegrityKey)
///     .CompleteAsync(rawSignature);
/// </code>
/// </example>
public static class CadesDeferredSigner
{
    /// <summary>Creates a builder that prepares a two-phase CAdES signature of <paramref name="data"/>.</summary>
    /// <param name="data">The document bytes to sign. The array is copied.</param>
    /// <returns>A builder that needs <c>WithCertificate</c> and <c>WithSessionIntegrityKey</c> before <c>PrepareAsync</c>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="data"/> is null.</exception>
    public static CadesDeferredSignerBuilder Document(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        return new CadesDeferredSignerBuilder(new CadesSignerBuilder(data, logger: null), session: null, sessionIntegrityKey: null);
    }

    /// <summary>
    /// Creates a builder that prepares a two-phase co-signature: a new signer over the same content, added to
    /// <paramref name="existingSignature"/> (a .p7s or .p7m) when the session is completed. See <see cref="CadesSigner.CoSign"/>.
    /// </summary>
    /// <param name="existingSignature">The existing CMS signature. It travels in the session.</param>
    /// <param name="data">The signed content; required for a detached .p7s, ignored for an attached .p7m.</param>
    /// <returns>A builder that needs <c>WithCertificate</c> and <c>WithSessionIntegrityKey</c> before <c>PrepareAsync</c>.</returns>
    /// <exception cref="ArgumentException">Detached signature without <paramref name="data"/>, or data that the existing signature does not cover.</exception>
    public static CadesDeferredSignerBuilder CoSign(byte[] existingSignature, byte[]? data = null) =>
        new(CadesSigner.CoSign(existingSignature, data), session: null, sessionIntegrityKey: null);

    /// <summary>
    /// Creates a builder that prepares a two-phase countersignature of signer <paramref name="signerIndex"/> of
    /// <paramref name="existingSignature"/> (RFC 5652 §11.4). The bytes to sign are the signed attributes over that
    /// signer's signature value. See <see cref="CadesSigner.CounterSign"/>.
    /// </summary>
    /// <param name="existingSignature">The existing CMS signature. It travels in the session.</param>
    /// <param name="signerIndex">The signer to countersign.</param>
    /// <returns>A builder that needs <c>WithCertificate</c> and <c>WithSessionIntegrityKey</c> before <c>PrepareAsync</c>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">There is no such signer.</exception>
    public static CadesDeferredSignerBuilder CounterSign(byte[] existingSignature, int signerIndex = 0) =>
        new(CadesSigner.CounterSign(existingSignature, signerIndex), session: null, sessionIntegrityKey: null);

    /// <summary>Resumes a session prepared by <see cref="CadesDeferredSignerBuilder.PrepareAsync(CancellationToken)"/>.</summary>
    /// <param name="sessionData">The session returned by phase one.</param>
    /// <param name="sessionIntegrityKey">The server-owned HMAC key given in phase one.</param>
    /// <returns>A builder that completes the session.</returns>
    /// <exception cref="ArgumentException">The data is not a CAdES deferred session, or the key has less than 32 bytes.</exception>
    /// <exception cref="System.Security.Cryptography.CryptographicException">The session was changed, or the key is not the one of phase one.</exception>
    public static CadesDeferredSignerBuilder Resume(byte[] sessionData, byte[] sessionIntegrityKey)
    {
        ArgumentNullException.ThrowIfNull(sessionData);
        ArgumentOutOfRangeException.ThrowIfZero(sessionData.Length);
        ArgumentNullException.ThrowIfNull(sessionIntegrityKey);
        CadesDeferredSession session = CadesDeferredSession.Read(sessionData, sessionIntegrityKey);
        return new CadesDeferredSignerBuilder(CadesSignerBuilder.ForDeferredCompletion(session), session, sessionIntegrityKey: null);
    }
}
