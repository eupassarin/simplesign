using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;
using SimpleSign.Signers.Pkcs11.Internal;
using SimpleSign.Signers.Pkcs11.Interop;

namespace SimpleSign.Signers.Pkcs11;

/// <summary>
/// Signs with a private key that stays on an A3 token, smartcard or HSM, through the device's
/// PKCS#11 driver. Works with every SimpleSign signer that accepts an <see cref="IExternalSigner"/>
/// (PAdES, CAdES, XAdES, deferred and batch signing).
/// </summary>
/// <remarks>
/// <para>
/// The hash is computed by SimpleSign with the BCL; the token only performs the key operation
/// (CKM_RSA_PKCS, CKM_RSA_PKCS_PSS or CKM_ECDSA), which every PKCS#11 token supports.
/// </para>
/// <para>
/// An instance keeps one logged-in session open until it is disposed. Calls to
/// <see cref="SignAsync"/> are serialized, so one instance can be shared by concurrent signers.
/// Disposing logs out, closes the session and disposes <see cref="Certificate"/> and <see cref="Chain"/>.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// using var token = Pkcs11Signer.Open(new Pkcs11SignerOptions
/// {
///     LibraryPath = "/usr/lib/libaetpkss.so",
///     Pin = pin,
/// });
/// byte[] signed = await PadesSigner.Document(pdf)
///     .WithExternalSigner(token.Certificate, token, token.Chain)
///     .SignAsync();
/// </code>
/// </example>
public sealed class Pkcs11Signer : IExternalSigner, IDisposable
{
    private readonly Pkcs11Module _module;
    private readonly ulong _session;
    private readonly ulong _key;
    private readonly Pkcs11KeyAlgorithm _keyAlgorithm;
    private readonly bool _loggedIn;
    private readonly ILogger _logger;
#if NET9_0_OR_GREATER
    private readonly Lock _gate = new();
#else
    private readonly object _gate = new();
#endif
    private bool _disposed;

    private Pkcs11Signer(
        Pkcs11Module module,
        ulong session,
        TokenKey key,
        bool loggedIn,
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> chain,
        string tokenLabel,
        ILogger logger)
    {
        _module = module;
        _session = session;
        _key = key.Handle;
        _keyAlgorithm = key.Algorithm;
        _loggedIn = loggedIn;
        _logger = logger;
        Certificate = certificate;
        Chain = chain;
        TokenLabel = tokenLabel;
    }

    /// <summary>The signer's certificate, read from the token.</summary>
    public X509Certificate2 Certificate { get; }

    /// <summary>The CA certificates stored on the same token (often the issuing chain). May be empty.</summary>
    public IReadOnlyList<X509Certificate2> Chain { get; }

    /// <summary>The label of the token in use.</summary>
    public string TokenLabel { get; }

    /// <summary>
    /// Loads the PKCS#11 driver, opens a session on the selected token, logs in and selects the
    /// signing key and its certificate.
    /// </summary>
    /// <param name="options">The driver, token, key and PIN.</param>
    /// <returns>A signer ready for <see cref="SignAsync"/>. Dispose it when done.</returns>
    /// <exception cref="ArgumentException"><see cref="Pkcs11SignerOptions.LibraryPath"/> is null or whitespace.</exception>
    /// <exception cref="Pkcs11Exception">
    /// The driver cannot be loaded, no token or key matches the selection, the selection is
    /// ambiguous, the PIN is wrong or locked, or the driver reports another error.
    /// </exception>
    public static Pkcs11Signer Open(Pkcs11SignerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(options.LibraryPath))
        {
            throw new ArgumentException("The PKCS#11 library path is required.", nameof(options));
        }

        var module = Pkcs11Module.Acquire(options.LibraryPath);
        ulong? session = null;
        bool loggedIn = false;
        List<TokenCertificate> certificates = [];
        try
        {
            var (slot, info) = SelectToken(module, options);
            if ((info.Flags & CkConstants.CkfUserPinLocked) != 0)
            {
                throw new Pkcs11Exception(
                    $"The PIN of token '{info.Label}' is locked. Unlock it with the PUK in the token vendor's tool.");
            }

            session = module.OpenSession(slot);
            certificates = ReadCertificates(module, session.Value);
            loggedIn = Login(module, session.Value, info, options.Pin);
            var keys = ReadKeys(module, session.Value);
            var (key, certificate) = SelectKey(keys, certificates, options, info.Label);

            var chain = certificates
                .Where(c => !ReferenceEquals(c, certificate) && IsCertificateAuthority(c.Certificate))
                .ToList();
            foreach (var unused in certificates.Where(c => !ReferenceEquals(c, certificate) && !chain.Contains(c)))
            {
                unused.Certificate.Dispose();
            }

            var logger = options.Logger ?? NullLogger.Instance;
            logger.TokenOpened(info.Label, certificate.Certificate.Subject, chain.Count, loggedIn);
            return new Pkcs11Signer(
                module, session.Value, key, loggedIn, certificate.Certificate,
                chain.Select(c => c.Certificate).ToList().AsReadOnly(), info.Label, logger);
        }
        catch
        {
            foreach (var certificate in certificates)
            {
                certificate.Certificate.Dispose();
            }

            if (session is { } open)
            {
                if (loggedIn)
                {
                    module.Logout(open);
                }

                module.CloseSession(open);
            }

            module.Release();
            throw;
        }
    }

    /// <summary>
    /// Lists the tokens present for a PKCS#11 driver and the certificates on each, without a PIN.
    /// Use it to discover labels and thumbprints for <see cref="Pkcs11SignerOptions"/>.
    /// </summary>
    /// <param name="libraryPath">Path or name of the PKCS#11 library.</param>
    /// <returns>The tokens present. The caller owns the returned certificates.</returns>
    /// <exception cref="ArgumentException"><paramref name="libraryPath"/> is null or whitespace.</exception>
    /// <exception cref="Pkcs11Exception">The driver cannot be loaded or reports an error.</exception>
    public static IReadOnlyList<Pkcs11TokenInfo> ListTokens(string libraryPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(libraryPath);
        var module = Pkcs11Module.Acquire(libraryPath);
        try
        {
            var tokens = new List<Pkcs11TokenInfo>();
            foreach (var (slot, info) in InitializedTokens(module))
            {
                List<TokenCertificate> certificates = [];
                ulong? session = null;
                try
                {
                    session = module.OpenSession(slot);
                    certificates = ReadCertificates(module, session.Value);
                }
                catch (Pkcs11Exception)
                {
                    // A token that cannot be read is still listed, without certificates.
                }
                finally
                {
                    if (session is { } open)
                    {
                        module.CloseSession(open);
                    }
                }

                tokens.Add(new Pkcs11TokenInfo(
                    slot,
                    info.Label,
                    info.Manufacturer,
                    info.Model,
                    info.SerialNumber,
                    IsLoginRequired: (info.Flags & CkConstants.CkfLoginRequired) != 0,
                    HasProtectedAuthenticationPath: (info.Flags & CkConstants.CkfProtectedAuthenticationPath) != 0,
                    IsPinLocked: (info.Flags & CkConstants.CkfUserPinLocked) != 0,
                    certificates.Select(c => new Pkcs11CertificateInfo(c.Label, c.Id, c.Certificate)).ToList().AsReadOnly()));
            }

            return tokens.AsReadOnly();
        }
        finally
        {
            module.Release();
        }
    }

    /// <inheritdoc />
    /// <exception cref="NotSupportedException">The requested algorithm is not supported or does not match the token key.</exception>
    /// <exception cref="Pkcs11Exception">The token refused to sign.</exception>
    /// <exception cref="ObjectDisposedException">The signer was disposed.</exception>
    public ValueTask<ReadOnlyMemory<byte>> SignAsync(ExternalSigningRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        var plan = Pkcs11SignatureEncoder.Prepare(request, _keyAlgorithm, _module.Layout);

        byte[] signature;
        long started = Stopwatch.GetTimestamp();
        _logger.SignRequested(plan.Mechanism, plan.Data.Length);
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            signature = _module.Sign(_session, _key, plan.Mechanism, plan.MechanismParameter, plan.Data);
        }

        _logger.SignCompleted(signature.Length, (long)Stopwatch.GetElapsedTime(started).TotalMilliseconds);

        return ValueTask.FromResult<ReadOnlyMemory<byte>>(
            plan.IsEcdsa ? Pkcs11SignatureEncoder.EcdsaRawToDer(signature) : signature);
    }

    /// <summary>Logs out, closes the session, releases the driver and disposes the certificates.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            if (_loggedIn)
            {
                _module.Logout(_session);
            }

            _module.CloseSession(_session);
            _module.Release();
        }

        _logger.SessionClosed(TokenLabel);
        Certificate.Dispose();
        foreach (var certificate in Chain)
        {
            certificate.Dispose();
        }
    }

    private static (ulong Slot, CkTokenInfo Info) SelectToken(Pkcs11Module module, Pkcs11SignerOptions options)
    {
        var tokens = InitializedTokens(module);
        if (tokens.Count == 0)
        {
            throw new Pkcs11Exception("No token is connected (the PKCS#11 driver found no slot with a token).");
        }

        var matches = tokens
            .Where(t => options.SlotId is not { } slot || t.Slot == slot)
            .Where(t => options.TokenLabel is null || string.Equals(t.Info.Label, options.TokenLabel, StringComparison.Ordinal))
            .Where(t => options.TokenSerial is null || string.Equals(t.Info.SerialNumber, options.TokenSerial, StringComparison.OrdinalIgnoreCase))
            .ToList();

        return matches.Count switch
        {
            1 => matches[0],
            0 => throw new Pkcs11Exception($"No token matches the selection. Tokens present: {DescribeTokens(tokens)}."),
            _ => throw new Pkcs11Exception(
                $"More than one token is present; set TokenLabel, TokenSerial or SlotId. Tokens present: {DescribeTokens(matches)}."),
        };
    }

    /// <summary>The tokens present and initialized (blank tokens, such as SoftHSM's free slot, are skipped).</summary>
    private static List<(ulong Slot, CkTokenInfo Info)> InitializedTokens(Pkcs11Module module) =>
    [
        .. module.GetSlotsWithToken()
            .Select(slot => (Slot: slot, Info: module.GetTokenInfo(slot)))
            .Where(t => (t.Info.Flags & CkConstants.CkfTokenInitialized) != 0),
    ];

    private static bool Login(Pkcs11Module module, ulong session, CkTokenInfo info, string? pin)
    {
        if (pin is not null)
        {
            byte[] utf8 = Encoding.UTF8.GetBytes(pin);
            try
            {
                return module.Login(session, utf8);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(utf8);
            }
        }

        if ((info.Flags & CkConstants.CkfProtectedAuthenticationPath) != 0)
        {
            return module.Login(session, null);
        }

        if ((info.Flags & CkConstants.CkfLoginRequired) != 0)
        {
            throw new Pkcs11Exception($"Token '{info.Label}' requires a PIN; set Pkcs11SignerOptions.Pin.");
        }

        return false;
    }

    private static List<TokenCertificate> ReadCertificates(Pkcs11Module module, ulong session)
    {
        var handles = module.FindObjects(session,
        [
            (CkConstants.CkaClass, module.EncodeULong(CkConstants.CkoCertificate)),
            (CkConstants.CkaCertificateType, module.EncodeULong(CkConstants.CkcX509)),
        ]);

        var certificates = new List<TokenCertificate>();
        foreach (ulong handle in handles)
        {
            byte[]? value = module.GetAttribute(session, handle, CkConstants.CkaValue);
            if (value is null)
            {
                continue;
            }

            X509Certificate2 certificate;
            try
            {
                certificate = CertificateLoader.LoadCertificate(value);
            }
            catch (CryptographicException)
            {
                continue;
            }

            certificates.Add(new TokenCertificate(
                ReadLabel(module, session, handle),
                module.GetAttribute(session, handle, CkConstants.CkaId) ?? [],
                certificate));
        }

        return certificates;
    }

    private static List<TokenKey> ReadKeys(Pkcs11Module module, ulong session)
    {
        var handles = module.FindObjects(session,
        [
            (CkConstants.CkaClass, module.EncodeULong(CkConstants.CkoPrivateKey)),
        ]);

        var keys = new List<TokenKey>();
        foreach (ulong handle in handles)
        {
            byte[]? keyType = module.GetAttribute(session, handle, CkConstants.CkaKeyType);
            Pkcs11KeyAlgorithm? algorithm = keyType is null ? null : Pkcs11Module.DecodeULong(keyType) switch
            {
                CkConstants.CkkRsa => Pkcs11KeyAlgorithm.Rsa,
                CkConstants.CkkEc => Pkcs11KeyAlgorithm.Ec,
                _ => null,
            };

            if (algorithm is { } known)
            {
                keys.Add(new TokenKey(
                    handle,
                    ReadLabel(module, session, handle),
                    module.GetAttribute(session, handle, CkConstants.CkaId) ?? [],
                    known));
            }
        }

        return keys;
    }

    private static (TokenKey Key, TokenCertificate Certificate) SelectKey(
        List<TokenKey> keys,
        List<TokenCertificate> certificates,
        Pkcs11SignerOptions options,
        string tokenLabel)
    {
        if (keys.Count == 0)
        {
            throw new Pkcs11Exception($"No RSA or EC private key was found on token '{tokenLabel}'.");
        }

        var pairs = new List<(TokenKey Key, TokenCertificate Certificate)>();
        foreach (var key in keys)
        {
            var certificate = certificates.Find(c => key.Id.Length > 0 && c.Id.AsSpan().SequenceEqual(key.Id))
                ?? certificates.Find(c => key.Label is not null && c.Label == key.Label);
            if (certificate is not null)
            {
                pairs.Add((key, certificate));
            }
        }

        if (pairs.Count == 0)
        {
            throw new Pkcs11Exception(
                $"Token '{tokenLabel}' has private keys but no certificate with the same CKA_ID or label.");
        }

        var matches = pairs
            .Where(p => options.KeyLabel is null || p.Key.Label == options.KeyLabel || p.Certificate.Label == options.KeyLabel)
            .Where(p => options.KeyId is not { } id || p.Key.Id.AsSpan().SequenceEqual(id.Span))
            .Where(p => options.CertificateThumbprint is null
                || string.Equals(p.Certificate.Certificate.Thumbprint, options.CertificateThumbprint, StringComparison.OrdinalIgnoreCase))
            .ToList();

        return matches.Count switch
        {
            1 => matches[0],
            0 => throw new Pkcs11Exception(
                $"No key on token '{tokenLabel}' matches the selection. Keys present: {DescribeKeys(pairs)}."),
            _ => throw new Pkcs11Exception(
                $"Token '{tokenLabel}' has more than one signing key; set KeyLabel, KeyId or CertificateThumbprint. Keys present: {DescribeKeys(matches)}."),
        };
    }

    private static string? ReadLabel(Pkcs11Module module, ulong session, ulong handle) =>
        module.GetAttribute(session, handle, CkConstants.CkaLabel) is { } label ? Encoding.UTF8.GetString(label) : null;

    private static bool IsCertificateAuthority(X509Certificate2 certificate) =>
        certificate.Extensions.OfType<X509BasicConstraintsExtension>().Any(e => e.CertificateAuthority);

    private static string DescribeTokens(IEnumerable<(ulong Slot, CkTokenInfo Info)> tokens) =>
        string.Join(", ", tokens.Select(t => $"'{t.Info.Label}' (serial {t.Info.SerialNumber}, slot {t.Slot})"));

    private static string DescribeKeys(IEnumerable<(TokenKey Key, TokenCertificate Certificate)> pairs) =>
        string.Join(", ", pairs.Select(p =>
            $"'{p.Key.Label ?? p.Certificate.Label}' ({p.Certificate.Certificate.Subject}, thumbprint {p.Certificate.Certificate.Thumbprint})"));

    private sealed record TokenCertificate(string? Label, byte[] Id, X509Certificate2 Certificate);

    private sealed record TokenKey(ulong Handle, string? Label, byte[] Id, Pkcs11KeyAlgorithm Algorithm);
}
