using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Constants;
using SimpleSign.Agent.Localization;
using SimpleSign.Agent.Services;
using SimpleSign.Core.Signing;
using SimpleSign.Signers.Pkcs11;

namespace SimpleSign.Agent.Server;

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

/// <summary>
/// The filters of <c>GET /api/certificates</c>: <c>source</c>, <c>filterIcpBrasil</c> (the former ICP-Brasil filter,
/// by issuer name and policy OID), the trust frameworks of <c>country</c>/<c>trust</c> (by chain to their anchors) and
/// <c>signingOnly</c> (valid now, with a signing key usage).
/// </summary>
internal sealed record CertificateQuery(
    string Source = "all", bool IcpBrasilOnly = false, IReadOnlyList<TrustFramework>? Frameworks = null, bool SigningOnly = false);

/// <summary>Signs the agent's /api/sign requests with a store or token key, after the user consents.</summary>
internal sealed class AgentSigner(AgentServices services, TokenSessionCache sessions, Func<CancellationToken, Task<IReadOnlyList<CertificateEntry>>>? certificates = null)
{
    public const int MaxItems = 100;

    private readonly Func<CancellationToken, Task<IReadOnlyList<CertificateEntry>>> _certificates = certificates ?? AllCertificatesAsync;

    /// <summary>The OS store certificates and those of the connected tokens.</summary>
    public static async Task<IReadOnlyList<CertificateEntry>> AllCertificatesAsync(CancellationToken cancellationToken) =>
        [.. CertificateService.ListStore(), .. (await CertificateService.ListTokensAsync(cancellationToken)).Certificates];

    /// <summary>The store and token certificates the agent exposes, filtered as <paramref name="query"/> asks.</summary>
    public async Task<List<AgentCertificate>> ListAsync(CertificateQuery query, CancellationToken cancellationToken)
    {
        var entries = new List<CertificateEntry>();
        foreach (var e in await _certificates(cancellationToken))
        {
            bool fromSource = query.Source switch
            {
                "pkcs11" => e.Kind == CertificateSourceKind.Token,
                "store" => e.Kind != CertificateSourceKind.Token,
                _ => true,
            };
            if (fromSource
                && (!query.IcpBrasilOnly || e.IsIcpBrasil)
                && (!query.SigningOnly || TrustFrameworks.CanSignNow(e.Certificate))
                && (query.Frameworks is null || await services.TrustFrameworks.AnyTrustsAsync(query.Frameworks, e.Certificate, cancellationToken)))
            {
                entries.Add(e);
            }
        }

        return [.. entries
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
                PolicyIssue = e.PolicyIssue,
            })];
    }

    /// <summary>Asks the user, then signs every item. Null when the user refused.</summary>
    public async Task<List<AgentSignResult>?> SignAsync(string originLabel, AgentSignRequest request, CancellationToken cancellationToken)
    {
        var items = request.SignRequests ?? [];
        var entry = (await _certificates(cancellationToken)).FirstOrDefault(e => Same(e, request.Thumbprint))
            ?? throw new KeyNotFoundException(L.T("api.certificateNotFound", request.Thumbprint));
        var payloads = Inspect(items, entry.Certificate);
        string what = request.DocumentName is { Length: > 0 } name ? $"“{Trim(name, 80)}”" : L.T("consent.sign.documents", items.Count);
        string digest = payloads[0].Inspection.Digests[0].ToShortString();
        string message = L.T("consent.sign.message", originLabel, what, entry.Holder) + " "
            + (payloads.Count == 1 ? L.T("consent.sign.digest", digest) : L.T("consent.sign.digests", digest, payloads.Count - 1));
        var decision = await services.Dialogs.AskConsentAsync(new ConsentRequest(originLabel, L.T("consent.sign.title"),
            message, entry.Holder, OfferRemember: false));
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

            return [.. await Task.WhenAll(payloads.Select(p => SignWithTokenAsync(signer, p, hash, cancellationToken)))];
        }

        return [.. payloads.Select(p => SignWithStore(entry.Certificate, p, hash))];
    }

    /// <summary>
    /// Decodes and inspects every item before the user is asked: only CMS signed attributes (naming the chosen
    /// certificate when they name one) or an XML-DSig SignedInfo are signed, never raw bytes.
    /// </summary>
    /// <exception cref="AgentRequestException">An item is not base64 or not data the agent signs.</exception>
    internal static List<Payload> Inspect(IReadOnlyList<AgentSignRequestItem> items, X509Certificate2 certificate)
    {
        var payloads = new List<Payload>(items.Count);
        for (int i = 0; i < items.Count; i++)
        {
            string id = items[i].Id ?? i.ToString(System.Globalization.CultureInfo.InvariantCulture);
            byte[] data;
            try
            {
                data = Convert.FromBase64String(items[i].AuthenticatedAttributeBase64 ?? "");
            }
            catch (FormatException)
            {
                throw new AgentRequestException(L.T("api.itemNotBase64", id));
            }

            var inspection = DataToSignInspector.Inspect(data, certificate);
            if (!inspection.IsAccepted)
            {
                throw new AgentRequestException(L.T("api.itemRefused", id, inspection.Message ?? ""));
            }

            payloads.Add(new Payload(id, data, inspection));
        }

        return payloads;
    }

    /// <summary>An item of a request, decoded and inspected.</summary>
    internal sealed record Payload(string Id, byte[] Data, DataToSignInspection Inspection);

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
            pin = await services.Dialogs.AskSecretAsync(L.T("pin.title"),
                L.T("pin.message", entry.Token.TokenLabel.Trim(), entry.Holder), L.T("pin.confirm"));
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

    private static AgentSignResult SignWithStore(X509Certificate2 certificate, Payload payload, HashAlgorithmName hash)
    {
        try
        {
            using var rsa = certificate.GetRSAPrivateKey();
            if (rsa is not null)
            {
                return new AgentSignResult { Id = payload.Id, SignedHashBase64 = Convert.ToBase64String(rsa.SignData(payload.Data, hash, RSASignaturePadding.Pkcs1)) };
            }

            using var ecdsa = certificate.GetECDsaPrivateKey();
            return ecdsa is not null
                ? new AgentSignResult { Id = payload.Id, SignedHashBase64 = Convert.ToBase64String(ecdsa.SignData(payload.Data, hash)) }
                : new AgentSignResult { Id = payload.Id, Error = L.T("api.unsupportedKey") };
        }
        catch (CryptographicException ex)
        {
            return new AgentSignResult { Id = payload.Id, Error = ex.Message };
        }
    }

    private static async Task<AgentSignResult> SignWithTokenAsync(
        Pkcs11Signer signer, Payload payload, HashAlgorithmName hash, CancellationToken cancellationToken)
    {
        try
        {
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
                new ExternalSigningRequest(payload.Data, hash, algorithm, payload.Inspection.Kind!.Value), cancellationToken);
            // The store path returns ECDSA as IEEE P1363 (r||s), like the former HostSigner; tokens give DER.
            byte[] value = rsa ? signature.ToArray() : DerToP1363(signature.Span, signer.Certificate);
            return new AgentSignResult { Id = payload.Id, SignedHashBase64 = Convert.ToBase64String(value) };
        }
        catch (Exception ex) when (ex is CryptographicException or Pkcs11Exception or NotSupportedException)
        {
            return new AgentSignResult { Id = payload.Id, Error = ex.Message };
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

    /// <summary>Whether the hash algorithm of a request is one the agent signs with (SHA-256 when absent).</summary>
    internal static bool IsSupportedHash(string? name) =>
        name is null || name.Replace("-", "", StringComparison.Ordinal).ToUpperInvariant() is "SHA256" or "SHA384" or "SHA512";

    private static HashAlgorithmName ParseHash(string? name) =>
        name?.Replace("-", "", StringComparison.Ordinal).ToUpperInvariant() switch
        {
            null or "SHA256" => HashAlgorithmName.SHA256,
            "SHA384" => HashAlgorithmName.SHA384,
            "SHA512" => HashAlgorithmName.SHA512,
            _ => throw new ArgumentException(L.T("api.hashUnsupported", name), nameof(name)),
        };

    private static string Trim(string value, int max) => value.Length <= max ? value : value[..max] + "…";
}

/// <summary>A request the agent refuses before asking the user (answered with 400).</summary>
internal sealed class AgentRequestException : Exception
{
    public AgentRequestException()
    {
    }

    public AgentRequestException(string message)
        : base(message)
    {
    }

    public AgentRequestException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
