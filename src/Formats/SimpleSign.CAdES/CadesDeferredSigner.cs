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
