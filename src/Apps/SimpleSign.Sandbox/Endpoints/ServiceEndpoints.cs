using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text;
using SimpleSign.Sandbox.Pki;
using SimpleSign.Sandbox.Services;

namespace SimpleSign.Sandbox.Endpoints;

/// <summary>
/// The network services a client reaches through the URLs in the certificates and the settings
/// the Sandbox publishes: AIA (issuer certificates), CRLs, the RFC 3161 TSA and the CSC v2 API.
/// </summary>
internal static class ServiceEndpoints
{
    /// <summary>Basic credentials the authenticated TSA accepts.</summary>
    public const string TsaUser = "sandbox";

    public const string TsaPassword = "sandbox-tsa";

    private const string FaultItem = "sandbox.fault";

    private static readonly string[] s_prefixes = ["/aia/", "/crl/", "/tsa/", "/csc/", "/root.pem", "/chain.pem"];

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
                _ when path.StartsWith("/tsa/", StringComparison.Ordinal) => "TSA",
                _ when path.StartsWith("/csc/", StringComparison.Ordinal) => "CSC",
                _ => "AIA",
            };
            context.RequestServices.GetRequiredService<RequestLog>().Add(context.Request.Method, path + context.Request.QueryString, context.Response.StatusCode,
                service, context.Items[FaultItem] as string, watch.ElapsedMilliseconds, context.Connection.RemoteIpAddress?.ToString());
        });

        // AIA: the issuer certificates (DER), and the chain as PEM for people.
        app.MapGet("/aia/root.cer", (SandboxPki pki) => Results.Bytes(pki.Root.RawData, "application/pkix-cert"));
        app.MapGet("/aia/intermediate.cer", (SandboxPki pki) => Results.Bytes(pki.Intermediate.RawData, "application/pkix-cert"));
        app.MapGet("/root.pem", (SandboxPki pki) => Results.Text(pki.Root.ExportCertificatePem() + "\n", "application/x-pem-file"));
        app.MapGet("/chain.pem", (SandboxPki pki) =>
            Results.Text(pki.Intermediate.ExportCertificatePem() + "\n" + pki.Root.ExportCertificatePem() + "\n", "application/x-pem-file"));

        // CRLs.
        app.MapGet("/crl/{name}", async (string name, SandboxPki pki, HttpContext context, CancellationToken ct) =>
        {
            if (name is not ("root.crl" or "intermediate.crl"))
            {
                return Results.NotFound();
            }

            var faults = pki.Faults;
            switch (faults.Crl)
            {
                case CrlFault.Down:
                    context.Items[FaultItem] = "Down";
                    return Results.Text("Sandbox failure: the CRL server is down.", statusCode: StatusCodes.Status503ServiceUnavailable);
                case CrlFault.Slow:
                    context.Items[FaultItem] = $"Slow ({faults.CrlDelayMs} ms)";
                    await Task.Delay(faults.CrlDelayMs, ct);
                    break;
                case CrlFault.Expired:
                    context.Items[FaultItem] = "Expired";
                    var (expiredRoot, expiredIntermediate) = pki.ExpiredCrls();
                    return Results.Bytes(name == "root.crl" ? expiredRoot : expiredIntermediate, "application/pkix-crl");
                default:
                    break;
            }

            return Results.Bytes(name == "root.crl" ? pki.RootCrl : pki.IntermediateCrl, "application/pkix-crl");
        });

        // RFC 3161 TSA: /tsa/tsr (and /tsa/archive), /tsa/authenticated (HTTP Basic), /tsa/untrusted.
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

    private static async Task<IResult> TimestampAsync(string kind, HttpContext context, SandboxPki pki, TsaServices tsas, CancellationToken ct)
    {
        if (kind is not ("tsr" or "archive" or "authenticated" or "untrusted"))
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
        if (faults.Tsa == TsaFault.Down)
        {
            context.Items[FaultItem] = "Down";
            return Results.Text("Sandbox failure: the TSA is down.", statusCode: StatusCodes.Status503ServiceUnavailable);
        }

        if (faults.Tsa == TsaFault.Slow)
        {
            context.Items[FaultItem] = $"Slow ({faults.TsaDelayMs} ms)";
            await Task.Delay(faults.TsaDelayMs, ct);
        }

        using var body = new MemoryStream();
        await context.Request.Body.CopyToAsync(body, ct);
        bool untrusted = faults.Tsa == TsaFault.Untrusted || kind == "untrusted";
        if (faults.Tsa == TsaFault.Untrusted)
        {
            context.Items[FaultItem] = "Untrusted";
        }

        byte[] reply;
        try
        {
            reply = (untrusted ? tsas.Untrusted : tsas.Trusted).Respond(body.ToArray());
        }
        catch (System.Formats.Asn1.AsnContentException)
        {
            return Results.Text("The body is not an RFC 3161 TimeStampReq.", statusCode: StatusCodes.Status400BadRequest);
        }

        if (faults.Tsa == TsaFault.InvalidToken && reply.Length > 64)
        {
            // Change bytes inside the token's signature: it still parses and no longer verifies.
            context.Items[FaultItem] = "InvalidToken";
            reply[^20] ^= 0xFF;
            reply[^21] ^= 0xFF;
        }

        return Results.Bytes(reply, "application/timestamp-reply");
    }
}

/// <summary>The two TSAs: one in the Sandbox's chain, one outside every trust anchor.</summary>
internal sealed class TsaServices(SandboxPki pki)
{
    public SandboxTsa Trusted { get; } = new(pki.Tsa, pki.TsaKey, pki.Chain);

    public SandboxTsa Untrusted { get; } = new(pki.UntrustedTsa, pki.UntrustedTsaKey, []);
}
