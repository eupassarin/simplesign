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

/// <summary>
/// The Sandbox's trust scheme: its list of trusted lists, its trusted list, and the operators' certificates (PEM); and
/// <paramref name="IofeUrl"/>, a trusted list laid out as INDECOPI's (territory PE), signed by the same operator as the
/// trusted list (<paramref name="TlSignerUrl"/>).
/// </summary>
public sealed record TrustedListsInfo(string LotlUrl, string TlUrl, string LotlSignerUrl, string TlSignerUrl, string Territory, string IofeUrl);

public sealed record SandboxUrls(string RootCertificate, string IntermediateCertificate, string RootPem, string ChainPem, string RootCrl, string IntermediateCrl);

/// <summary>The URLs of one CA: its certificate, its CRL over HTTP, HTTPS and LDAP, and its OCSP responder.</summary>
public sealed record AuthorityUrls(string Id, string Certificate, string Crl, string HttpsCrl, string LdapCrl, string Ocsp);

public sealed record TsaInfo(string Url, string AuthenticatedUrl, string UntrustedUrl, string RevokedUrl, string WrongNameUrl, string WrongName, string User, string Password,
    string ExpiredUrl, string IofeUrl);

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

/// <summary>
/// A signing certificate to issue with a chosen subject: <see cref="Subject"/> as a DN string, or <see cref="Rdns"/>
/// (most specific first, as a DN string reads). Accepted attributes: CN (required), serialNumber, C, O, OU, L, ST, T,
/// G/GN, SN, organizationIdentifier; 1 to 64 characters each, 16 at most.
/// </summary>
/// <param name="Subject">The subject, such as <c>CN=Juan Pérez, serialNumber=PNOPE-12345678, C=PE</c>.</param>
/// <param name="Rdns">The subject as attributes, instead of <paramref name="Subject"/>.</param>
/// <param name="KeyType">The key; default RSA 2048.</param>
/// <param name="KeyUsage">
/// Key usages (<c>DigitalSignature</c>, <c>NonRepudiation</c>, <c>KeyEncipherment</c>, <c>DataEncipherment</c>,
/// <c>KeyAgreement</c>); default digitalSignature and nonRepudiation; an empty list leaves the extension out.
/// </param>
/// <param name="Title">What the UI shows; default the CN.</param>
/// <param name="ValidityDays">Days of validity from now, 1 to 825; default 365.</param>
public sealed record CustomCertificateRequest(
    string? Subject = null,
    IReadOnlyList<SubjectAttribute>? Rdns = null,
    SandboxKeyType? KeyType = null,
    IReadOnlyList<string>? KeyUsage = null,
    string? Title = null,
    int? ValidityDays = null);

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
        admin.MapPost("/certificates/custom", (CustomCertificateRequest request, SandboxPki pki) => IssueCustom(request, pki));
        admin.MapGet("/certificates/{id}", (string id, SandboxPki pki) =>
            Found(pki, id, () => Results.Ok(View(pki.Certificate(id)))));
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
        // One failure at a time: the members left out keep their value.
        admin.MapMethods("/faults", [HttpMethods.Patch], (SandboxFaultsPatch patch, SandboxPki pki) => pki.UpdateFaults(patch.ApplyTo));
        // Every failure off; the delays and the OCSP signer (a choice, not a failure) stay.
        admin.MapDelete("/faults", (SandboxPki pki) => pki.UpdateFaults(f => f with
        {
            Tsa = TsaFault.None,
            Crl = CrlFault.None,
            Ocsp = OcspFault.None,
            TrustedList = TlFault.None,
        }));
        admin.MapGet("/log", (long? after, int? limit, string? service, RequestLog log) =>
            log.Since(after ?? 0, limit is { } n ? Math.Clamp(n, 1, RequestLog.Capacity) : null, string.IsNullOrEmpty(service) ? null : service));
        admin.MapDelete("/log", (RequestLog log) =>
        {
            log.Clear();
            return Results.NoContent();
        });
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
                ServiceEndpoints.TsaUser, ServiceEndpoints.TsaPassword, Url("tsa/expired"), Url("tsa/iofe")),
            new CscInfo(csc.BaseUri.AbsoluteUri, SandboxCsc.ClientId, SandboxCsc.ClientSecret, SandboxCsc.ServiceToken, SandboxCsc.Pin, SandboxCsc.Otp,
                [.. csc.Credentials.Select(c => new CscCredentialView(c.Id, c.Description, c.CertificateId, c.AuthMode, c.Scal, c.MultiSign))]),
            SandboxPki.PfxPassword,
            // What a client puts in OutboundHttpPolicy.LoopbackOrigins to reach this Sandbox on this machine.
            [.. new[] { pki.BaseUrl, pki.HttpsBaseUrl, pki.LdapBaseUrl }.Select(u => u.GetLeftPart(UriPartial.Authority))],
            new TrustedListsInfo(Url("tl/lotl.xml"), Url("tl/tl.xml"), Url("tl/lotl-signer.pem"), Url("tl/tl-signer.pem"), SandboxTrustedLists.Territory,
                Url("tl/iofe.xml")));
    }

    private const X509KeyUsageFlags LeafUsages = X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation
        | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyAgreement;

    internal static IResult IssueCustom(CustomCertificateRequest request, SandboxPki pki)
    {
        if ((request.Subject is { Length: > 0 }) == (request.Rdns is { Count: > 0 }))
        {
            return Results.BadRequest(new { error = "Give either subject (a DN string) or rdns." });
        }

        if (request.ValidityDays is < 1 or > 825)
        {
            return Results.BadRequest(new { error = "validityDays must be between 1 and 825." });
        }

        if (request.Title is { Length: > 128 })
        {
            return Results.BadRequest(new { error = "title may have 128 characters at most." });
        }

        X509KeyUsageFlags? usage = null;
        if (request.KeyUsage is { } names)
        {
            var flags = X509KeyUsageFlags.None;
            foreach (string name in names)
            {
                if (!Enum.TryParse<X509KeyUsageFlags>(name, ignoreCase: true, out var flag) || flag == X509KeyUsageFlags.None || (flag & ~LeafUsages) != 0)
                {
                    return Results.BadRequest(new { error = $"Unknown or CA-only key usage '{name}': use DigitalSignature, NonRepudiation, KeyEncipherment, DataEncipherment or KeyAgreement." });
                }

                flags |= flag;
            }

            usage = flags;
        }

        try
        {
            var subject = request.Subject is { Length: > 0 } dn ? SandboxSubject.Parse(dn) : SandboxSubject.Build(request.Rdns!);
            var issued = pki.IssueCustom(subject, request.Title, request.KeyType ?? SandboxKeyType.Rsa2048, usage,
                TimeSpan.FromDays(request.ValidityDays ?? 365));
            return Results.Created($"/api/certificates/{issued.Id}", View(issued));
        }
        catch (ArgumentException ex)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
        catch (InvalidOperationException ex)
        {
            return Results.Conflict(new { error = ex.Message });
        }
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
