using System.Net;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Sandbox.Pki;
using SimpleSign.Sandbox.Services;

namespace SimpleSign.Sandbox.Endpoints;

/// <summary>What a client needs to use this Sandbox: its URLs and the test credentials of its services.</summary>
public sealed record SandboxInfo(
    string Name,
    string Version,
    string BaseUrl,
    string HttpsBaseUrl,
    string LdapBaseUrl,
    DateTimeOffset CreatedAt,
    string RootThumbprint,
    string RootSubject,
    SandboxUrls Urls,
    IReadOnlyList<AuthorityUrls> Authorities,
    TsaInfo Tsa,
    CscInfo Csc,
    string PfxPassword,
    IReadOnlyList<string> LoopbackOrigins,
    TrustedListsInfo TrustedLists);

/// <summary>The Sandbox's trust scheme: its list of trusted lists, its trusted list, and the operators' certificates (PEM).</summary>
public sealed record TrustedListsInfo(string LotlUrl, string TlUrl, string LotlSignerUrl, string TlSignerUrl, string Territory);

public sealed record SandboxUrls(string RootCertificate, string IntermediateCertificate, string RootPem, string ChainPem, string RootCrl, string IntermediateCrl);

/// <summary>The URLs of one CA: its certificate, its CRL over HTTP, HTTPS and LDAP, and its OCSP responder.</summary>
public sealed record AuthorityUrls(string Id, string Certificate, string Crl, string HttpsCrl, string LdapCrl, string Ocsp);

public sealed record TsaInfo(string Url, string AuthenticatedUrl, string UntrustedUrl, string RevokedUrl, string WrongNameUrl, string WrongName, string User, string Password);

public sealed record CscInfo(string BaseUrl, string ClientId, string ClientSecret, string ServiceToken, string Pin, string Otp, IReadOnlyList<CscCredentialView> Credentials);

public sealed record CscCredentialView(string Id, string Description, string CertificateId, string AuthMode, string Scal, int MultiSign);

/// <summary>A certificate as the UI shows it.</summary>
public sealed record CertificateView(
    string Id,
    string Title,
    string Description,
    string Subject,
    string Issuer,
    string? IssuerId,
    string SerialNumber,
    string Thumbprint,
    string NotBefore,
    string NotAfter,
    string? KeyType,
    string? Usage,
    string? Pointers,
    string? Problem,
    bool IsUsable,
    DateTimeOffset? RevokedAt,
    string? RevocationReason,
    string? Publication);

/// <summary>The PKI: the CAs, the TSA outside the chain and the issued certificates.</summary>
public sealed record PkiView(IReadOnlyList<CertificateView> Authorities, CertificateView UntrustedTsa, IReadOnlyList<CertificateView> Certificates);

/// <summary>A revocation: the reason (an <see cref="X509RevocationReason"/> name) and where it is published.</summary>
public sealed record RevokeRequest(string? Reason, RevocationPublication Publication = RevocationPublication.Both);

/// <summary>The API of the UI: the PKI, revocations, failures and the request log.</summary>
internal static class AdminEndpoints
{
    public static void Map(WebApplication app, SandboxOptions options)
    {
        var api = app.MapGroup("/api");
        api.MapGet("/info", Info);

        // What changes the Sandbox, or hands out private keys, answers this machine only unless allowed.
        var admin = api.MapGroup("");
        if (!options.AllowRemoteAdmin)
        {
            admin.AddEndpointFilter(async (context, next) =>
                context.HttpContext.Connection.RemoteIpAddress is { } address && !IPAddress.IsLoopback(address)
                    ? Results.Problem("The admin API answers this machine only (start the Sandbox with --allow-remote-admin).", statusCode: StatusCodes.Status403Forbidden)
                    : await next(context));
        }

        admin.MapGet("/pki", (SandboxPki pki) => new PkiView(
            [.. pki.Authorities.Select(View)],
            View("untrusted-tsa", "TSA outside the chain", pki.UntrustedTsa),
            [.. pki.Certificates.Select(View)]));
        admin.MapPost("/certificates/short-lived", (int? seconds, SandboxPki pki) =>
            Results.File(pki.IssueShortLived(TimeSpan.FromSeconds(Math.Clamp(seconds ?? 3, 1, 3600))), "application/x-pkcs12", "short-lived.pfx"));
        admin.MapGet("/certificates/{id}/pfx", (string id, SandboxPki pki) =>
            Found(pki, id, () => Results.File(pki.Pfx(id), "application/x-pkcs12", $"{id}.pfx")));
        admin.MapGet("/certificates/{id}/cer", (string id, SandboxPki pki) =>
            Found(pki, id, () => Results.File(pki.Certificate(id).Certificate.RawData, "application/pkix-cert", $"{id}.cer")));
        admin.MapPost("/certificates/{id}/revoke", (string id, RevokeRequest? body, SandboxPki pki) =>
            Found(pki, id, () =>
            {
                if (body?.Reason is { } reason && !Enum.TryParse<X509RevocationReason>(reason, out _))
                {
                    return Results.BadRequest(new { error = $"Unknown revocation reason '{reason}'." });
                }

                pki.Revoke(id, body?.Reason, body?.Publication ?? RevocationPublication.Both);
                return Results.Ok(View(pki.Certificate(id)));
            }));
        admin.MapPost("/certificates/{id}/unrevoke", (string id, SandboxPki pki) =>
            Found(pki, id, () =>
            {
                pki.Unrevoke(id);
                return Results.Ok(View(pki.Certificate(id)));
            }));
        admin.MapGet("/faults", (SandboxPki pki) => pki.Faults);
        admin.MapPut("/faults", (SandboxFaults faults, SandboxPki pki) =>
        {
            pki.Faults = faults;
            return pki.Faults;
        });
        admin.MapGet("/log", (long? after, RequestLog log) => log.Since(after ?? 0));
        admin.MapPost("/reset", (SandboxPki pki, RequestLog log) =>
        {
            pki.Reset();
            log.Clear();
            return Results.NoContent();
        });
    }

    internal static SandboxInfo Info(SandboxPki pki, SandboxCsc csc)
    {
        string Url(string relative) => new Uri(pki.BaseUrl, relative).AbsoluteUri;
        return new SandboxInfo(
            pki.Name,
            typeof(AdminEndpoints).Assembly.GetName().Version?.ToString(3) ?? "?",
            pki.BaseUrl.AbsoluteUri,
            pki.HttpsBaseUrl.AbsoluteUri,
            pki.LdapBaseUrl.AbsoluteUri,
            pki.CreatedAt,
            pki.Root.Thumbprint,
            pki.Root.Subject,
            new SandboxUrls(pki.CertificateUrl(SandboxPki.RootId).AbsoluteUri, pki.CertificateUrl(SandboxPki.IntermediateId).AbsoluteUri, Url("root.pem"), Url("chain.pem"),
                pki.CrlUrl(SandboxPki.RootId).AbsoluteUri, pki.CrlUrl(SandboxPki.IntermediateId).AbsoluteUri),
            [.. pki.Authorities.Select(a => new AuthorityUrls(a.Id, pki.CertificateUrl(a.Id).AbsoluteUri, pki.CrlUrl(a.Id).AbsoluteUri,
                pki.HttpsCrlUrl(a.Id).AbsoluteUri, pki.LdapCrlUrl(a.Id).OriginalString, pki.OcspUrl(a.Id).AbsoluteUri))],
            new TsaInfo(Url("tsa/tsr"), Url("tsa/authenticated"), Url("tsa/untrusted"), Url("tsa/revoked"), Url("tsa/wrong-name"), ServiceEndpoints.WrongTsaName,
                ServiceEndpoints.TsaUser, ServiceEndpoints.TsaPassword),
            new CscInfo(csc.BaseUri.AbsoluteUri, SandboxCsc.ClientId, SandboxCsc.ClientSecret, SandboxCsc.ServiceToken, SandboxCsc.Pin, SandboxCsc.Otp,
                [.. csc.Credentials.Select(c => new CscCredentialView(c.Id, c.Description, c.CertificateId, c.AuthMode, c.Scal, c.MultiSign))]),
            SandboxPki.PfxPassword,
            // What a client puts in OutboundHttpPolicy.LoopbackOrigins to reach this Sandbox on this machine.
            [.. new[] { pki.BaseUrl, pki.HttpsBaseUrl, pki.LdapBaseUrl }.Select(u => u.GetLeftPart(UriPartial.Authority))],
            new TrustedListsInfo(Url("tl/lotl.xml"), Url("tl/tl.xml"), Url("tl/lotl-signer.pem"), Url("tl/tl-signer.pem"), SandboxTrustedLists.Territory));
    }

    private static IResult Found(SandboxPki pki, string id, Func<IResult> action) =>
        pki.Certificates.Any(c => c.Id == id) ? action() : Results.NotFound(new { error = $"No certificate '{id}'." });

    private static CertificateView View(SandboxCertificate c) =>
        View(c.Id, c.Title, c.Certificate) with
        {
            Description = c.Description,
            IssuerId = c.IssuerId,
            KeyType = c.KeyType.ToString(),
            Usage = c.Usage.ToString(),
            Pointers = c.Pointers.ToString(),
            Problem = c.Problem,
            IsUsable = c.IsUsable,
            RevokedAt = c.RevokedAt,
            RevocationReason = c.RevocationReason,
            Publication = c.RevokedAt is null ? null : c.Publication.ToString(),
        };

    private static CertificateView View(SandboxAuthority a) =>
        View(a.Id, a.Title, a.Certificate) with
        {
            IssuerId = a.IssuerId,
            Problem = a.Problem,
            IsUsable = a.Problem is null,
            RevokedAt = a.RevokedAt,
            RevocationReason = a.RevocationReason,
        };

    private static CertificateView View(string id, string title, X509Certificate2 certificate) => new(
        id, title, "", certificate.Subject, certificate.Issuer, null, certificate.SerialNumber, certificate.Thumbprint,
        certificate.NotBefore.ToUniversalTime().ToString("O", System.Globalization.CultureInfo.InvariantCulture),
        certificate.NotAfter.ToUniversalTime().ToString("O", System.Globalization.CultureInfo.InvariantCulture),
        null, null, null, null, true, null, null, null);
}
