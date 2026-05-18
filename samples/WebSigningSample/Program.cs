using System.Security.Cryptography.X509Certificates;
using SimpleSign.PAdES;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAntiforgery();

var app = builder.Build();
app.UseStaticFiles();

// POST /api/prepare — receives PDF files + certificate, returns hashes to sign
app.MapPost("/api/prepare", async (HttpRequest request) =>
{
    var form = await request.ReadFormAsync();
    var certBase64 = form["certificateBase64"].ToString();

    if (string.IsNullOrEmpty(certBase64))
    {
        return Results.BadRequest(new { error = "certificateBase64 is required" });
    }

#if NET9_0_OR_GREATER
    using var cert = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(certBase64));
#else
    using var cert = new X509Certificate2(Convert.FromBase64String(certBase64));
#endif

    var files = form.Files;

    if (files.Count == 0)
    {
        return Results.BadRequest(new { error = "No PDF files provided" });
    }

    var preparedDocs = new List<object>();

    for (int i = 0; i < files.Count; i++)
    {
        var file = files[i];
        using var ms = new MemoryStream();
        await file.CopyToAsync(ms);
        var pdfBytes = ms.ToArray();

        try
        {
            var signerName = cert.GetNameInfo(X509NameType.SimpleName, false) ?? "Signer";
            var deferredBuilder = new DeferredSignerBuilder(pdfBytes, cert)
                .WithSignerName(signerName);

            var reason = form["reason"].ToString();
            var location = form["location"].ToString();

            if (!string.IsNullOrWhiteSpace(reason))
            {
                deferredBuilder = deferredBuilder.WithReason(reason);
            }

            if (!string.IsNullOrWhiteSpace(location))
            {
                deferredBuilder = deferredBuilder.WithLocation(location);
            }

            var prepared = await deferredBuilder.PrepareAsync();

            preparedDocs.Add(new
            {
                index = i,
                fileName = file.FileName,
                hashBase64 = Convert.ToBase64String(prepared.HashToSign),
                sessionDataBase64 = Convert.ToBase64String(prepared.SessionData),
                digestAlgorithm = prepared.DigestAlgorithm,
                signatureAlgorithmOid = prepared.SignatureAlgorithmOid
            });
        }
        catch (Exception ex)
        {
            preparedDocs.Add(new
            {
                index = i,
                fileName = file.FileName,
                error = ex.Message
            });
        }
    }

    return Results.Ok(preparedDocs);
}).DisableAntiforgery();

// POST /api/complete — receives sessionData + signature, returns signed PDF
app.MapPost("/api/complete", async (HttpRequest request) =>
{
    var body = await request.ReadFromJsonAsync<CompleteRequest>();
    if (body is null || string.IsNullOrEmpty(body.SignedHashBase64) || string.IsNullOrEmpty(body.SignedHashBase64))
    {
        return Results.BadRequest(new { error = "FileId and SignedHashBase64 are required" });
    }

    try
    {
        var sessionData = Convert.FromBase64String(body.SessionDataBase64);
        var signature = Convert.FromBase64String(body.SignedHashBase64);

        var signedPdf = await DeferredSigner.CompleteAsync(sessionData, signature);

        return Results.Ok(new { signedPdfBase64 = Convert.ToBase64String(signedPdf) });
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
}).DisableAntiforgery();

// Fallback to index.html
app.MapFallbackToFile("index.html");

app.Run();

public sealed class CompleteRequest
{
    public string SessionDataBase64 { get; set; } = "";
    public string SignedHashBase64 { get; set; } = "";
}
