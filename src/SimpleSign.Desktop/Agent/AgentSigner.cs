using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Signing;
using SimpleSign.Desktop.Services;
using SimpleSign.Signers.Pkcs11;

namespace SimpleSign.Desktop.Agent;

/// <summary>Keeps token sessions (with their PIN) open for a while when the user allows it.</summary>
internal sealed class TokenSessionCache(TimeProvider? time = null) : IDisposable
{
    private readonly Dictionary<string, (Pkcs11Signer Signer, DateTimeOffset Expires)> _sessions = new(StringComparer.Ordinal);
    private readonly Lock _gate = new();
    private readonly TimeProvider _time = time ?? TimeProvider.System;

    public Pkcs11Signer? Get(string key)
    {
        lock (_gate)
        {
            if (_sessions.TryGetValue(key, out var s) && s.Expires > _time.GetUtcNow())
            {
                return s.Signer;
            }

            if (s.Signer is not null)
            {
                s.Signer.Dispose();
                _sessions.Remove(key);
            }

            return null;
        }
    }

    public void Put(string key, Pkcs11Signer signer, TimeSpan lifetime)
    {
        lock (_gate)
        {
            if (_sessions.Remove(key, out var old) && !ReferenceEquals(old.Signer, signer))
            {
                old.Signer.Dispose();
            }

            _sessions[key] = (signer, _time.GetUtcNow() + lifetime);
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            foreach (var s in _sessions.Values)
            {
                s.Signer.Dispose();
            }

            _sessions.Clear();
        }
    }
}

/// <summary>Signs the agent's /api/sign requests with a store or token key, after the user consents.</summary>
internal sealed class AgentSigner(AppServices services, TokenSessionCache sessions, Func<CancellationToken, Task<IReadOnlyList<CertificateEntry>>>? certificates = null)
{
    public const int MaxItems = 100;

    private readonly Func<CancellationToken, Task<IReadOnlyList<CertificateEntry>>> _certificates = certificates ?? AllCertificatesAsync;

    /// <summary>The OS store certificates and those of the connected tokens.</summary>
    public static async Task<IReadOnlyList<CertificateEntry>> AllCertificatesAsync(CancellationToken cancellationToken) =>
        [.. CertificateService.ListStore(), .. (await CertificateService.ListTokensAsync(cancellationToken)).Certificates];

    /// <summary>The store and token certificates the agent exposes.</summary>
    public async Task<List<AgentCertificate>> ListAsync(string source, bool icpBrasilOnly, CancellationToken cancellationToken)
    {
        var entries = (await _certificates(cancellationToken))
            .Where(e => source switch
            {
                "pkcs11" => e.Kind == CertificateSourceKind.Token,
                "store" => e.Kind != CertificateSourceKind.Token,
                _ => true,
            });
        return [.. entries
            .Where(e => !icpBrasilOnly || e.IsIcpBrasil)
            .Select(e => new AgentCertificate
            {
                Name = e.Certificate.Subject,
                Thumbprint = e.Certificate.Thumbprint,
                IssuerName = e.Certificate.Issuer,
                NotBefore = e.Certificate.NotBefore.ToString("o"),
                ExpireDate = e.Certificate.NotAfter.ToString("o"),
                SignatureAlgorithm = e.Certificate.GetRSAPublicKey() is not null ? "RSA" : "ECDSA",
                HashAlgorithm = "SHA256",
                UserCertificateBase64 = Convert.ToBase64String(e.Certificate.RawData),
                Source = e.Kind == CertificateSourceKind.Token ? "pkcs11" : "store",
                TokenLabel = e.Token?.TokenLabel.Trim(),
            })];
    }

    /// <summary>Asks the user, then signs every item. Null when the user refused.</summary>
    public async Task<List<AgentSignResult>?> SignAsync(string originLabel, AgentSignRequest request, CancellationToken cancellationToken)
    {
        var items = request.SignRequests ?? [];
        var entry = (await _certificates(cancellationToken)).FirstOrDefault(e => Same(e, request.Thumbprint))
            ?? throw new KeyNotFoundException($"Certificado não encontrado: {request.Thumbprint}");
        string what = request.DocumentName is { Length: > 0 } name ? $"“{Trim(name, 80)}”" : $"{items.Count} documento(s)";
        var decision = await services.Dialogs.AskConsentAsync(new ConsentRequest(originLabel, "Assinar documento",
            $"{originLabel} quer assinar {what} com o certificado de {entry.Holder}.", entry.Holder, OfferRemember: false));
        if (decision == ConsentDecision.Deny)
        {
            return null;
        }

        var hash = ParseHash(request.HashAlgorithm);
        if (entry.Kind == CertificateSourceKind.Token)
        {
            var signer = await OpenTokenAsync(entry);
            if (signer is null)
            {
                return null;
            }

            return [.. await Task.WhenAll(items.Select((item, i) => SignWithTokenAsync(signer, item, i, hash, cancellationToken)))];
        }

        return [.. items.Select((item, i) => SignWithStore(entry.Certificate, item, i, hash))];
    }

    private async Task<Pkcs11Signer?> OpenTokenAsync(CertificateEntry entry)
    {
        string key = entry.Token!.TokenSerial + "|" + entry.Certificate.Thumbprint;
        if (sessions.Get(key) is { } cached)
        {
            return cached;
        }

        string? pin = null;
        if (!entry.Token.HasPinPad)
        {
            pin = await services.Dialogs.AskSecretAsync("PIN do token",
                $"Digite o PIN de {entry.Token.TokenLabel.Trim()} para assinar com {entry.Holder}.", "Assinar");
            if (pin is null)
            {
                return null;
            }
        }

        var credential = await Task.Run(() => CertificateService.Open(entry, pin));
        var signer = (Pkcs11Signer)credential.External!;
        int minutes = services.Settings.Current.PinCacheMinutes;
        sessions.Put(key, signer, minutes > 0 ? TimeSpan.FromMinutes(minutes) : TimeSpan.FromSeconds(30));
        return signer;
    }

    private static AgentSignResult SignWithStore(X509Certificate2 certificate, AgentSignRequestItem item, int index, HashAlgorithmName hash)
    {
        string id = item.Id ?? index.ToString(System.Globalization.CultureInfo.InvariantCulture);
        try
        {
            byte[] data = Convert.FromBase64String(item.AuthenticatedAttributeBase64 ?? "");
            using var rsa = certificate.GetRSAPrivateKey();
            if (rsa is not null)
            {
                return new AgentSignResult { Id = id, SignedHashBase64 = Convert.ToBase64String(rsa.SignData(data, hash, RSASignaturePadding.Pkcs1)) };
            }

            using var ecdsa = certificate.GetECDsaPrivateKey();
            return ecdsa is not null
                ? new AgentSignResult { Id = id, SignedHashBase64 = Convert.ToBase64String(ecdsa.SignData(data, hash)) }
                : new AgentSignResult { Id = id, Error = "Tipo de chave não suportado." };
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException)
        {
            return new AgentSignResult { Id = id, Error = ex.Message };
        }
    }

    private static async Task<AgentSignResult> SignWithTokenAsync(
        Pkcs11Signer signer, AgentSignRequestItem item, int index, HashAlgorithmName hash, CancellationToken cancellationToken)
    {
        string id = item.Id ?? index.ToString(System.Globalization.CultureInfo.InvariantCulture);
        try
        {
            byte[] data = Convert.FromBase64String(item.AuthenticatedAttributeBase64 ?? "");
            bool rsa = signer.Certificate.GetRSAPublicKey() is { } key && Dispose(key);
            string algorithm = (rsa, hash.Name) switch
            {
                (true, "SHA384") => Oids.RsaSha384,
                (true, "SHA512") => Oids.RsaSha512,
                (true, _) => Oids.RsaSha256,
                (false, "SHA384") => Oids.EcdsaSha384,
                (false, "SHA512") => Oids.EcdsaSha512,
                _ => Oids.EcdsaSha256,
            };
            var signature = await signer.SignAsync(
                new ExternalSigningRequest(data, hash, algorithm, ExternalSigningPayloadKind.CmsSignedAttributes), cancellationToken);
            // The store path returns ECDSA as IEEE P1363 (r||s), like the former HostSigner; tokens give DER.
            byte[] value = rsa ? signature.ToArray() : DerToP1363(signature.Span, signer.Certificate);
            return new AgentSignResult { Id = id, SignedHashBase64 = Convert.ToBase64String(value) };
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException or Pkcs11Exception or NotSupportedException)
        {
            return new AgentSignResult { Id = id, Error = ex.Message };
        }
    }

    internal static byte[] DerToP1363(ReadOnlySpan<byte> der, X509Certificate2 certificate)
    {
        using var ec = certificate.GetECDsaPublicKey()!;
        int size = (ec.KeySize + 7) / 8;
        var sequence = new AsnReader(der.ToArray(), AsnEncodingRules.DER).ReadSequence();
        byte[] result = new byte[size * 2];
        Write(sequence.ReadIntegerBytes().Span, result.AsSpan(0, size));
        Write(sequence.ReadIntegerBytes().Span, result.AsSpan(size, size));
        return result;

        static void Write(ReadOnlySpan<byte> integer, Span<byte> target)
        {
            integer = integer.TrimStart((byte)0);
            integer.CopyTo(target[(target.Length - integer.Length)..]);
        }
    }

    private static bool Dispose(IDisposable key)
    {
        key.Dispose();
        return true;
    }

    private static bool Same(CertificateEntry entry, string? thumbprint) =>
        string.Equals(entry.Certificate.Thumbprint, thumbprint?.Replace(" ", "", StringComparison.Ordinal), StringComparison.OrdinalIgnoreCase);

    private static HashAlgorithmName ParseHash(string? name) =>
        name?.Replace("-", "", StringComparison.Ordinal).ToUpperInvariant() switch
        {
            "SHA384" => HashAlgorithmName.SHA384,
            "SHA512" => HashAlgorithmName.SHA512,
            _ => HashAlgorithmName.SHA256,
        };

    private static string Trim(string value, int max) => value.Length <= max ? value : value[..max] + "…";
}
