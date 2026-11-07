using System.Diagnostics;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SimpleSign.Sandbox.Pki;
using SimpleSign.Sandbox.Services;

namespace SimpleSign.Sandbox.Endpoints;

/// <summary>
/// The network services a client reaches through the URLs in the certificates and the settings
/// the Sandbox publishes: AIA (issuer certificates), CRLs, OCSP, the RFC 3161 TSA and the CSC v2
/// API. They answer on the HTTP port and, the same, on the HTTPS port.
/// </summary>
internal static class ServiceEndpoints
{
    /// <summary>Basic credentials the authenticated TSA accepts.</summary>
    public const string TsaUser = "sandbox";

    public const string TsaPassword = "sandbox-tsa";

    /// <summary>The name the /tsa/wrong-name TSA writes in its tokens instead of its own.</summary>
    public const string WrongTsaName = "CN=Some Other TSA, O=Elsewhere";

    internal const string FaultItem = "sandbox.fault";

    private static readonly string[] s_prefixes = ["/aia/", "/crl/", "/ocsp/", "/tsa/", "/csc/", "/root.pem", "/chain.pem"];

    public static void Map(WebApplication app)
    {
        // Every service request goes to the live log, with the failure applied to it.
        app.Use(async (context, next) =>
        {
            string path = context.Request.Path.Value ?? "/";
            if (!s_prefixes.Any(p => path.StartsWith(p, StringComparison.Ordinal)))
            {
                await next();
                return;
            }

            var watch = Stopwatch.StartNew();
            await next();
            string service = path switch
            {
                _ when path.StartsWith("/crl/", StringComparison.Ordinal) => "CRL",
                _ when path.StartsWith("/ocsp/", StringComparison.Ordinal) => "OCSP",
                _ when path.StartsWith("/tsa/", StringComparison.Ordinal) => "TSA",
                _ when path.StartsWith("/csc/", StringComparison.Ordinal) => "CSC",
                _ => "AIA",
            };
            context.RequestServices.GetRequiredService<RequestLog>().Add(context.Request.Method, path + context.Request.QueryString, context.Response.StatusCode,
                context.Request.IsHttps ? service + " (HTTPS)" : service, context.Items[FaultItem] as string, watch.ElapsedMilliseconds,
                context.Connection.RemoteIpAddress?.ToString());
        });

        // AIA: the CA certificates (DER), and the main chain as PEM for people.
        app.MapGet("/aia/{name}", (string name, SandboxPki pki) =>
            name.EndsWith(".cer", StringComparison.Ordinal) && pki.Authorities.FirstOrDefault(a => a.Id == name[..^4]) is { } authority
                ? Results.Bytes(authority.Certificate.RawData, "application/pkix-cert")
                : Results.NotFound());
        app.MapGet("/root.pem", (SandboxPki pki) => Results.Text(pki.Root.ExportCertificatePem() + "\n", "application/x-pem-file"));
        app.MapGet("/chain.pem", (SandboxPki pki) =>
            Results.Text(pki.Intermediate.ExportCertificatePem() + "\n" + pki.Root.ExportCertificatePem() + "\n", "application/x-pem-file"));

        // CRLs, one per CA.
        app.MapGet("/crl/{name}", async (string name, SandboxPki pki, HttpContext context, CancellationToken ct) =>
        {
            string caId = name.EndsWith(".crl", StringComparison.Ordinal) ? name[..^4] : "";
            if (!pki.Authorities.Any(a => a.Id == caId))
            {
                return Results.NotFound();
            }

            var faults = pki.Faults;
            if (faults.Crl != CrlFault.None)
            {
                context.Items[FaultItem] = faults.Crl == CrlFault.Slow ? $"Slow ({faults.CrlDelayMs} ms)" : faults.Crl.ToString();
            }

            switch (faults.Crl)
            {
                case CrlFault.Down:
                    return Results.Text("Sandbox failure: the CRL server is down.", statusCode: StatusCodes.Status503ServiceUnavailable);
                case CrlFault.Slow:
                    await Task.Delay(faults.CrlDelayMs, ct);
                    return Results.Bytes(pki.Crl(caId), "application/pkix-crl");
                default:
                    return Results.Bytes(pki.Crl(caId, faults.Crl), "application/pkix-crl");
            }
        });

        // OCSP (RFC 6960): POST, and GET with the base64 request in the path.
        app.MapPost("/ocsp/{caId}", async (string caId, HttpContext context, SandboxPki pki, OcspResponder responder, CancellationToken ct) =>
        {
            using var body = new MemoryStream();
            await context.Request.Body.CopyToAsync(body, ct);
            return await OcspAsync(caId, body.ToArray(), context, pki, responder, ct);
        });
        app.MapGet("/ocsp/{caId}/{**request}", async (string caId, string request, HttpContext context, SandboxPki pki, OcspResponder responder, CancellationToken ct) =>
        {
            byte[] der;
            try
            {
                string base64 = Uri.UnescapeDataString(request).Replace('-', '+').Replace('_', '/');
                der = Convert.FromBase64String(base64.PadRight(base64.Length + ((4 - (base64.Length % 4)) % 4), '='));
            }
            catch (FormatException)
            {
                return Results.Bytes(OcspResponder.Status(1), "application/ocsp-response");
            }

            return await OcspAsync(caId, der, context, pki, responder, ct);
        });

        // RFC 3161 TSA: /tsa/tsr (and /tsa/archive), /tsa/authenticated (HTTP Basic), /tsa/untrusted,
        // /tsa/revoked (its certificate is revoked) and /tsa/wrong-name (the token names another TSA).
        app.MapPost("/tsa/{kind}", TimestampAsync);

        // CSC v2 (the simulated provider is an HttpMessageHandler: requests are passed through).
        app.MapGet("/csc/v2/oauth2/authorize", async (HttpContext context, SandboxCsc csc, CancellationToken ct) =>
        {
            var request = new Uri(csc.BaseUri, "oauth2/authorize" + context.Request.QueryString);
            if (CscHttp.Query(request, "redirect_uri") is not { Length: > 0 } redirect || !Uri.TryCreate(redirect, UriKind.Absolute, out var redirectUri))
            {
                return Results.BadRequest("redirect_uri is required.");
            }

            // The simulated login page approves at once and sends the user back with the code.
            var back = await csc.AuthorizeAsync(request, redirectUri, ct);
            return Results.Redirect(back.AbsoluteUri);
        });
        app.Map("/csc/v2/{**path}", async (string path, HttpContext context, SandboxCsc csc, CancellationToken ct) =>
        {
            using var request = new HttpRequestMessage(new HttpMethod(context.Request.Method), new Uri(csc.BaseUri, path + context.Request.QueryString));
            using var body = new MemoryStream();
            await context.Request.Body.CopyToAsync(body, ct);
            request.Content = new ByteArrayContent(body.ToArray());
            if (context.Request.ContentType is { } type)
            {
                request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(type);
            }

            if (context.Request.Headers.Authorization.ToString() is { Length: > 0 } authorization)
            {
                request.Headers.Authorization = AuthenticationHeaderValue.Parse(authorization);
            }

            using var invoker = new HttpMessageInvoker(csc, disposeHandler: false);
            using var response = await invoker.SendAsync(request, ct);
            context.Response.StatusCode = (int)response.StatusCode;
            context.Response.ContentType = response.Content.Headers.ContentType?.ToString();
            await response.Content.CopyToAsync(context.Response.Body, ct);
        });
    }

    private static async Task<IResult> OcspAsync(string caId, byte[] request, HttpContext context, SandboxPki pki, OcspResponder responder, CancellationToken ct)
    {
        if (!pki.Authorities.Any(a => a.Id == caId))
        {
            return Results.NotFound();
        }

        var faults = pki.Faults;
        if (faults.Ocsp != OcspFault.None || faults.OcspSigner == OcspSigner.Delegated)
        {
            context.Items[FaultItem] = string.Join(", ", new[]
            {
                faults.Ocsp == OcspFault.None ? null : faults.Ocsp == OcspFault.Slow ? $"Slow ({faults.OcspDelayMs} ms)" : faults.Ocsp.ToString(),
                faults.OcspSigner == OcspSigner.Delegated ? "Delegated signer" : null,
            }.OfType<string>());
        }

        switch (faults.Ocsp)
        {
            case OcspFault.Down:
                return Results.Text("Sandbox failure: the OCSP responder is down.", statusCode: StatusCodes.Status503ServiceUnavailable);
            case OcspFault.Slow:
                await Task.Delay(faults.OcspDelayMs, ct);
                break;
            default:
                break;
        }

        try
        {
            return Results.Bytes(responder.Respond(caId, request, faults), "application/ocsp-response");
        }
        catch (System.Formats.Asn1.AsnContentException)
        {
            return Results.Bytes(OcspResponder.Status(1), "application/ocsp-response");
        }
    }

    private static async Task<IResult> TimestampAsync(string kind, HttpContext context, SandboxPki pki, CancellationToken ct)
    {
        if (kind is not ("tsr" or "archive" or "authenticated" or "untrusted" or "revoked" or "wrong-name"))
        {
            return Results.NotFound();
        }

        if (kind == "authenticated")
        {
            string expected = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{TsaUser}:{TsaPassword}"));
            if (context.Request.Headers.Authorization.ToString() != expected)
            {
                context.Response.Headers.WWWAuthenticate = "Basic realm=\"sandbox-tsa\"";
                return Results.Text($"This TSA requires HTTP Basic authentication ({TsaUser} / {TsaPassword}).", statusCode: StatusCodes.Status401Unauthorized);
            }
        }

        var faults = pki.Faults;
        if (faults.Tsa != TsaFault.None)
        {
            context.Items[FaultItem] = faults.Tsa == TsaFault.Slow ? $"Slow ({faults.TsaDelayMs} ms)" : faults.Tsa.ToString();
        }

        if (faults.Tsa == TsaFault.Down)
        {
            return Results.Text("Sandbox failure: the TSA is down.", statusCode: StatusCodes.Status503ServiceUnavailable);
        }

        if (faults.Tsa == TsaFault.Slow)
        {
            await Task.Delay(faults.TsaDelayMs, ct);
        }

        using var body = new MemoryStream();
        await context.Request.Body.CopyToAsync(body, ct);
        byte[] reply;
        try
        {
            reply = Stamp(pki, faults.Tsa == TsaFault.Untrusted ? "untrusted" : kind, body.ToArray());
        }
        catch (System.Formats.Asn1.AsnContentException)
        {
            return Results.Text("The body is not an RFC 3161 TimeStampReq.", statusCode: StatusCodes.Status400BadRequest);
        }

        if (faults.Tsa == TsaFault.InvalidToken && reply.Length > 64)
        {
            // Change bytes inside the token's signature: it still parses and no longer verifies.
            reply[^20] ^= 0xFF;
            reply[^21] ^= 0xFF;
        }

        return Results.Bytes(reply, "application/timestamp-reply");
    }

    /// <summary>Answers a TimeStampReq with the TSA of an endpoint, built from the current certificates.</summary>
    private static byte[] Stamp(SandboxPki pki, string kind, byte[] request)
    {
        if (kind == "untrusted")
        {
            return new SandboxTsa(pki.UntrustedTsa, pki.UntrustedTsaKey, []).Respond(request);
        }

        var certificate = pki.Certificate(kind == "revoked" ? "tsa-revoked" : "tsa");
        using var key = certificate.Certificate.GetRSAPrivateKey()!;
        return new SandboxTsa(certificate.Certificate, key, pki.ChainOf(certificate.Id),
            kind == "wrong-name" ? new X500DistinguishedName(WrongTsaName) : null).Respond(request);
    }
}
