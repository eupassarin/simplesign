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
    DateTimeOffset CreatedAt,
    string RootThumbprint,
    string RootSubject,
    SandboxUrls Urls,
    TsaInfo Tsa,
    CscInfo Csc,
    string PfxPassword);

public sealed record SandboxUrls(string RootCertificate, string IntermediateCertificate, string RootPem, string ChainPem, string RootCrl, string IntermediateCrl);

public sealed record TsaInfo(string Url, string AuthenticatedUrl, string UntrustedUrl, string User, string Password);

public sealed record CscInfo(string BaseUrl, string ClientId, string ClientSecret, string ServiceToken, string Pin, string Otp, IReadOnlyList<CscCredentialView> Credentials);

public sealed record CscCredentialView(string Id, string Description, string CertificateId, string AuthMode, string Scal, int MultiSign);

/// <summary>A certificate as the UI shows it.</summary>
public sealed record CertificateView(
    string Id,
    string Title,
    string Description,
    string Subject,
    string Issuer,
    string SerialNumber,
    string Thumbprint,
    string NotBefore,
    string NotAfter,
    string? KeyType,
    string? Problem,
    bool IsUsable,
    DateTimeOffset? RevokedAt,
    string? RevocationReason);

/// <summary>The PKI: the CAs, the TSAs and the issued certificates.</summary>
public sealed record PkiView(CertificateView Root, CertificateView Intermediate, CertificateView Tsa, CertificateView UntrustedTsa, IReadOnlyList<CertificateView> Certificates);

public sealed record RevokeRequest(string? Reason);

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
            View("root", "Root CA", pki.Root),
            View("intermediate", "Intermediate CA", pki.Intermediate),
            View("tsa", "TSA", pki.Tsa),
            View("untrusted-tsa", "TSA outside the chain", pki.UntrustedTsa),
            [.. pki.Certificates.Select(View)]));
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

                pki.Revoke(id, body?.Reason);
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
            pki.CreatedAt,
            pki.Root.Thumbprint,
            pki.Root.Subject,
            new SandboxUrls(pki.RootCertificateUrl.AbsoluteUri, pki.IntermediateCertificateUrl.AbsoluteUri, Url("root.pem"), Url("chain.pem"),
                pki.RootCrlUrl.AbsoluteUri, pki.IntermediateCrlUrl.AbsoluteUri),
            new TsaInfo(Url("tsa/tsr"), Url("tsa/authenticated"), Url("tsa/untrusted"), ServiceEndpoints.TsaUser, ServiceEndpoints.TsaPassword),
            new CscInfo(csc.BaseUri.AbsoluteUri, SandboxCsc.ClientId, SandboxCsc.ClientSecret, SandboxCsc.ServiceToken, SandboxCsc.Pin, SandboxCsc.Otp,
                [.. csc.Credentials.Select(c => new CscCredentialView(c.Id, c.Description, c.CertificateId, c.AuthMode, c.Scal, c.MultiSign))]),
            SandboxPki.PfxPassword);
    }

    private static IResult Found(SandboxPki pki, string id, Func<IResult> action) =>
        pki.Certificates.Any(c => c.Id == id) ? action() : Results.NotFound(new { error = $"No certificate '{id}'." });

    private static CertificateView View(SandboxCertificate c) =>
        View(c.Id, c.Title, c.Certificate) with
        {
            Description = c.Description,
            KeyType = c.KeyType.ToString(),
            Problem = c.Problem,
            IsUsable = c.IsUsable,
            RevokedAt = c.RevokedAt,
            RevocationReason = c.RevocationReason,
        };

    private static CertificateView View(string id, string title, X509Certificate2 certificate) => new(
        id, title, "", certificate.Subject, certificate.Issuer, certificate.SerialNumber, certificate.Thumbprint,
        certificate.NotBefore.ToUniversalTime().ToString("O", System.Globalization.CultureInfo.InvariantCulture),
        certificate.NotAfter.ToUniversalTime().ToString("O", System.Globalization.CultureInfo.InvariantCulture),
        null, null, true, null, null);
}
