using SimpleSign.TestBench.Sandbox;

namespace SimpleSign.TestBench.Endpoints;

/// <summary>Where a SimpleSign Sandbox answers.</summary>
public sealed record SandboxConnectRequest(string Url);

/// <summary>
/// The link to a SimpleSign Sandbox (src/Apps/SimpleSign.Sandbox): connect, disconnect, build the
/// signed samples again, and hand its root to an external validator (DSS).
/// </summary>
internal static class SandboxApi
{
    public static void Map(RouteGroupBuilder api)
    {
        var group = api.MapGroup("/sandbox");
        group.MapPost("/connect", async (SandboxConnectRequest body, SandboxEnvironment sandbox, SampleService samples, CancellationToken ct) =>
        {
            if (!Uri.TryCreate(body.Url, UriKind.Absolute, out var url) || url.Scheme is not ("http" or "https"))
            {
                return Results.BadRequest(new { error = Localization.L.T("Enter the Sandbox's address, such as http://localhost:5300.") });
            }

            try
            {
                await sandbox.ConnectAsync(url, ct);
            }
            catch (Exception ex) when (ex is HttpRequestException or System.Text.Json.JsonException or TaskCanceledException or InvalidOperationException)
            {
                return Results.BadRequest(new { error = Localization.L.T("No SimpleSign Sandbox answered at {0}: {1}", url.AbsoluteUri, ex.Message) });
            }

            await samples.RefreshAsync(ct);
            return Results.Ok(Api.Environment(sandbox));
        });
        group.MapPost("/disconnect", async (SandboxEnvironment sandbox, SampleService samples, CancellationToken ct) =>
        {
            sandbox.Disconnect();
            await samples.RefreshAsync(ct);
            return Api.Environment(sandbox);
        });
        group.MapPost("/samples", async (SampleService samples, SandboxEnvironment sandbox, CancellationToken ct) =>
        {
            await samples.RefreshAsync(ct);
            return Api.Environment(sandbox);
        });

        // The connected Sandbox's root and chain, so an external validator (DSS) can be told to trust it.
        group.MapGet("/root.pem", (SandboxEnvironment sandbox) => sandbox.Current is { } c
            ? Results.Text(c.Root.ExportCertificatePem() + "\n", "application/x-pem-file")
            : Results.NotFound());
        group.MapGet("/chain.pem", (SandboxEnvironment sandbox) => sandbox.Current is { } c
            ? Results.Text(c.Root.ExportCertificatePem() + "\n" + c.Intermediate.ExportCertificatePem() + "\n", "application/x-pem-file")
            : Results.NotFound());
    }
}

/// <summary>Builds the signed samples (validation, CAdES, XML) again from the connected Sandbox, or drops them without one.</summary>
internal sealed class SampleService(
    SandboxEnvironment sandbox,
    Documents.DocumentStore documents,
    Validation.ValidationSampleStore validation,
    Cades.CadesSampleStore cades,
    Xml.XmlSampleStore xml) : IDisposable
{
    private readonly SemaphoreSlim _gate = new(1, 1);

    public void Dispose() => _gate.Dispose();

    public async Task RefreshAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            validation.Samples = await Validation.InvalidSamples.CreateAsync(sandbox, documents, cancellationToken);
            cades.Samples = await Cades.CadesSamples.CreateAsync(sandbox, documents, cancellationToken);
            xml.Samples = await Xml.XmlSamples.CreateAsync(sandbox, documents, cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }
}
