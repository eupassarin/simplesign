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

            // The background build signs with the current connection's keys: stop it before they are released.
            await samples.StopAsync();
            try
            {
                await sandbox.ConnectAsync(url, ct);
            }
            catch (Exception ex) when (ex is HttpRequestException or System.Text.Json.JsonException or TaskCanceledException or InvalidOperationException)
            {
                _ = samples.Start(); // The connection did not change: build its samples again.
                return Results.BadRequest(new { error = Localization.L.T("No SimpleSign Sandbox answered at {0}: {1}", url.AbsoluteUri, ex.Message) });
            }

            // The samples are built in the background: the connection does not wait for them.
            _ = samples.Start();
            return Results.Ok(Api.Environment(sandbox));
        });
        group.MapPost("/disconnect", async (SandboxEnvironment sandbox, SampleService samples) =>
        {
            await samples.StopAsync();
            sandbox.Disconnect();
            _ = samples.Start();
            return Api.Environment(sandbox);
        });
        group.MapPost("/samples", async (SampleService samples, SandboxEnvironment sandbox, CancellationToken ct) =>
        {
            await samples.StopAsync(); // A build already running would only be done twice.
            await samples.Start().WaitAsync(ct);
            return Api.Environment(sandbox);
        });

        // The connected Sandbox's root and chain, so an external validator (DSS) can be told to trust it.
        group.MapGet("/root.pem", (SandboxEnvironment sandbox) => sandbox.Current is { } c
            ? Results.Text(c.Root.ExportCertificatePem() + "\n", "application/x-pem-file")
            : Results.NotFound());
        group.MapGet("/chain.pem", (SandboxEnvironment sandbox) => sandbox.Current is { } c
            ? Results.Text(c.Root.ExportCertificatePem() + "\n" + c.Intermediate.ExportCertificatePem() + "\n", "application/x-pem-file")
            : Results.NotFound());

        // The root as a .cer (DER), the file Adobe Acrobat/Reader imports as a trusted certificate.
        group.MapGet("/root.cer", (SandboxEnvironment sandbox) => RootCertificate(sandbox) is { } der
            ? Results.File(der, "application/pkix-cert", RootFileName)
            : Results.NotFound(new { error = Localization.L.T("No SimpleSign Sandbox is connected.") }));

        // The Sandbox's admin API (PKI, revocations, failures, request log), passed through as it is: the
        // Sandbox's controls in the TestBench's page call it here. Nothing is kept: the Sandbox stays the one source.
        group.Map("/admin/{**path}", Forward);
    }

    internal static async Task Forward(HttpContext context, string? path, SandboxEnvironment sandbox)
    {
        if (sandbox.Current is null)
        {
            context.Response.StatusCode = StatusCodes.Status409Conflict;
            await context.Response.WriteAsJsonAsync(new { error = Localization.L.T("No SimpleSign Sandbox is connected.") }, context.RequestAborted);
            return;
        }

        var request = context.Request;
        using var content = request.ContentLength is > 0 || request.Headers.TransferEncoding.Count > 0 ? new StreamContent(request.Body) : null;
        if (content is not null && request.ContentType is { } type)
        {
            content.Headers.TryAddWithoutValidation("Content-Type", type);
        }

        HttpResponseMessage response;
        try
        {
            response = await sandbox.ForwardAsync(new HttpMethod(request.Method), (path ?? "") + request.QueryString, content, context.RequestAborted);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            context.Response.StatusCode = StatusCodes.Status502BadGateway;
            await context.Response.WriteAsJsonAsync(new { error = Localization.L.T("The Sandbox did not answer: {0}", ex.Message) }, context.RequestAborted);
            return;
        }

        using (response)
        {
            context.Response.StatusCode = (int)response.StatusCode;
            if (response.Content.Headers.ContentType is { } contentType)
            {
                context.Response.ContentType = contentType.ToString();
            }

            if (response.Content.Headers.ContentDisposition is { } disposition)
            {
                context.Response.Headers.ContentDisposition = disposition.ToString();
            }

            await response.Content.CopyToAsync(context.Response.Body, context.RequestAborted);
        }
    }

    /// <summary>The name of the downloaded root.</summary>
    internal const string RootFileName = "simplesign-sandbox-root.cer";

    /// <summary>The connected Sandbox's root in DER, or null without a Sandbox.</summary>
    internal static byte[]? RootCertificate(SandboxEnvironment sandbox) =>
        sandbox.Current?.Root.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert);
}

/// <summary>
/// Builds the signed samples (validation, CAdES, XML) again from the connected Sandbox, or drops them without one.
/// Connecting starts it in the background (<see cref="Start"/>): the "expired" validation sample waits for a
/// certificate of a few seconds to expire, and the connection does not wait for that. Each list of samples is
/// read through <see cref="ValidationAsync"/>, <see cref="CadesAsync"/> and <see cref="XmlAsync"/>, which wait
/// only for their own list.
/// </summary>
internal sealed class SampleService(
    SandboxEnvironment sandbox,
    Documents.DocumentStore documents,
    Validation.ValidationSampleStore validation,
    Cades.CadesSampleStore cades,
    Xml.XmlSampleStore xml) : IDisposable
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Lock _lock = new();
    private Task _validation = Task.CompletedTask;
    private Task _cades = Task.CompletedTask;
    private Task _xml = Task.CompletedTask;
    private CancellationTokenSource _running = new();
    private Task _build = Task.CompletedTask;

    public void Dispose()
    {
        _running.Cancel();
        _running.Dispose();
        _gate.Dispose();
    }

    /// <summary>
    /// Starts building the samples again and returns the build without waiting for it (a build already running
    /// finishes first). <see cref="StopAsync"/> stops it.
    /// </summary>
    public Task Start()
    {
        Task build = RefreshAsync();
        lock (_lock)
        {
            _build = build;
        }

        return build;
    }

    /// <summary>
    /// Cancels the build running in the background and waits for it to stop: called before the connection changes,
    /// since the build signs with the current connection's keys, which a new connection releases.
    /// </summary>
    public async Task StopAsync()
    {
        Task build;
        lock (_lock)
        {
            build = _build;
            _running.Cancel();
            _running.Dispose();
            _running = new CancellationTokenSource();
        }

        try
        {
            await build;
        }
        catch (OperationCanceledException)
        {
            // Stopped, as asked.
        }
    }

    /// <summary>Builds the samples again and waits for all of them.</summary>
    public async Task RefreshAsync(CancellationToken cancellationToken = default)
    {
        CancellationToken stop;
        lock (_lock)
        {
            stop = _running.Token;
        }

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, stop);
        cancellationToken = linked.Token;
        // Readers wait for this build from now on, even while an earlier one still holds the gate: none of them
        // gets a list from before the connection that asked for it.
        var v = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var c = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var x = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (_lock)
        {
            (_validation, _cades, _xml) = (v.Task, c.Task, x.Task);
        }

        try
        {
            await _gate.WaitAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            v.TrySetResult();
            c.TrySetResult();
            x.TrySetResult();
            throw;
        }

        try
        {
            // The three lists do not depend on each other: built side by side, each readable as soon as it is done.
            await Task.WhenAll(
                Build(async () => validation.Samples = await Validation.InvalidSamples.CreateAsync(sandbox, documents, cancellationToken), "validation", v),
                Build(async () => cades.Samples = await Cades.CadesSamples.CreateAsync(sandbox, documents, cancellationToken), "CAdES", c),
                Build(async () => xml.Samples = await Xml.XmlSamples.CreateAsync(sandbox, documents, cancellationToken), "XML", x));
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>The validation samples, once built.</summary>
    public async Task<IReadOnlyList<Validation.ValidationSample>> ValidationAsync(CancellationToken cancellationToken = default)
    {
        await Pending(() => _validation).WaitAsync(cancellationToken);
        return validation.Samples;
    }

    /// <summary>The CAdES samples, once built.</summary>
    public async Task<IReadOnlyList<Cades.CadesSample>> CadesAsync(CancellationToken cancellationToken = default)
    {
        await Pending(() => _cades).WaitAsync(cancellationToken);
        return cades.Samples;
    }

    /// <summary>The XML samples, once built.</summary>
    public async Task<IReadOnlyList<Xml.XmlSample>> XmlAsync(CancellationToken cancellationToken = default)
    {
        await Pending(() => _xml).WaitAsync(cancellationToken);
        return xml.Samples;
    }

    private Task Pending(Func<Task> task)
    {
        lock (_lock)
        {
            return task();
        }
    }

    /// <summary>
    /// One list. Its readers are released when it is done, whatever happened: a failure keeps the list it had and is
    /// printed, so a reader never sees it as an exception.
    /// </summary>
    private static async Task Build(Func<Task> build, string name, TaskCompletionSource done)
    {
        try
        {
            await build();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Console.WriteLine($"The {name} samples could not be built: {ex.Message}");
        }
        finally
        {
            done.TrySetResult();
        }
    }
}
