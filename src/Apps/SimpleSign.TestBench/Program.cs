using System.Diagnostics;
using System.Text.Json.Serialization;
using Microsoft.Extensions.FileProviders;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Endpoints;
using SimpleSign.TestBench.Sandbox;
using SimpleSign.TestBench.Signing;

// SimpleSign TestBench: a local web app to try every PDF signing option of the library.
//   dotnet run --project src/Apps/SimpleSign.TestBench            (http://127.0.0.1:5199, opens the browser)
//   dotnet run --project src/Apps/SimpleSign.TestBench -- --port 5200 --no-browser
//   The test PKI and its services are a separate app, the SimpleSign Sandbox (src/Apps/SimpleSign.Sandbox):
//   connect it in Environment; the TestBench reconnects to it on the next start.
//   --sandbox URL: connect to this Sandbox at start (as SIMPLESIGN_SANDBOX_URL does).
int port = 5199;
bool openBrowser = true;
string? sandboxUrl = Environment.GetEnvironmentVariable("SIMPLESIGN_SANDBOX_URL");
for (int i = 0; i < args.Length; i++)
{
    if (args[i] == "--port" && i + 1 < args.Length && int.TryParse(args[i + 1], out int p))
    {
        port = p;
    }
    else if (args[i] == "--no-browser")
    {
        openBrowser = false;
    }
    else if (args[i] == "--sandbox" && i + 1 < args.Length)
    {
        sandboxUrl = args[++i];
    }
}

var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = args, ContentRootPath = AppContext.BaseDirectory });
builder.WebHost.ConfigureKestrel(o =>
{
    // Loopback only: the TestBench holds private keys and token sessions.
    o.Listen(System.Net.IPAddress.Loopback, port);
    o.Limits.MaxRequestBodySize = 60 * 1024 * 1024;
});
builder.Logging.SetMinimumLevel(LogLevel.Warning);
builder.Logging.AddFilter("Microsoft.Hosting.Lifetime", LogLevel.Information);
builder.Services.ConfigureHttpJsonOptions(o =>
{
    o.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
    o.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.Never;
});
builder.Services.AddSingleton(new SandboxEnvironment(SandboxEnvironment.DefaultStatePath));
builder.Services.AddSingleton<SampleService>();
builder.Services.AddSingleton<DocumentStore>();
builder.Services.AddSingleton<CredentialStore>();
builder.Services.AddSingleton<CredentialFactory>();
builder.Services.AddSingleton<SigningRunner>();
builder.Services.AddSingleton<StampPreviewService>();
builder.Services.AddSingleton<SimpleSign.TestBench.Validation.ValidationService>();
builder.Services.AddSingleton<SimpleSign.TestBench.Validation.InspectionService>();
builder.Services.AddSingleton<SimpleSign.TestBench.Validation.ValidationSampleStore>();
builder.Services.AddSingleton<SimpleSign.TestBench.Cades.CadesRunner>();
builder.Services.AddSingleton<SimpleSign.TestBench.Cades.CadesSampleStore>();
builder.Services.AddSingleton<SimpleSign.TestBench.Xml.XmlRunner>();
builder.Services.AddSingleton<SimpleSign.TestBench.Xml.XmlSampleStore>();
builder.Services.AddSingleton<SimpleSign.TestBench.CrossValidation.DssClient>();
builder.Services.AddSingleton<SimpleSign.TestBench.Runs.RunService>();

var app = builder.Build();

// The sample PDFs, the Sandbox connection (remembered, or the one given) and the signed samples, before serving.
var sandbox = app.Services.GetRequiredService<SandboxEnvironment>();
app.Services.GetRequiredService<DocumentStore>().AddSamples(await SampleDocuments.CreateAsync());
if (sandboxUrl is not null && Uri.TryCreate(sandboxUrl, UriKind.Absolute, out var givenSandbox))
{
    try
    {
        await sandbox.ConnectAsync(givenSandbox);
    }
    catch (HttpRequestException ex)
    {
        Console.WriteLine($"No SimpleSign Sandbox at {givenSandbox}: {ex.Message}");
    }
}
else
{
    await sandbox.ReconnectAsync();
}

await app.Services.GetRequiredService<SampleService>().RefreshAsync();

app.Use(async (context, next) =>
{
    // Only this app's pages may call the API (no CORS), and nothing is cached.
    context.Response.Headers.CacheControl = "no-store";
    context.Response.Headers.XContentTypeOptions = "nosniff";
    await next();
});

// The UI sends Accept-Language with the language the user picked (en-US, pt-BR or es).
app.UseRequestLocalization(o =>
{
    o.SetDefaultCulture("en-US");
    o.AddSupportedCultures(SimpleSign.TestBench.Localization.L.Cultures);
    o.AddSupportedUICultures(SimpleSign.TestBench.Localization.L.Cultures);
    o.FallBackToParentUICultures = true;
});

Api.Map(app);

// The UI: the project's web/dist when running from bin/ (so `npm run build` is picked up without
// rebuilding the .NET app), else the copy published next to the binary (wwwroot).
string? ui = new[]
{
    Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "web", "dist")),
    Path.Combine(AppContext.BaseDirectory, "wwwroot"),
}.FirstOrDefault(d => File.Exists(Path.Combine(d, "index.html")));
if (ui is not null)
{
    var files = new PhysicalFileProvider(ui);
    app.UseDefaultFiles(new DefaultFilesOptions { FileProvider = files });
    app.UseStaticFiles(new StaticFileOptions { FileProvider = files });
    app.MapFallback(async context =>
    {
        context.Response.ContentType = "text/html; charset=utf-8";
        await context.Response.SendFileAsync(Path.Combine(ui, "index.html"));
    });
}
else
{
    app.MapGet("/", () => Results.Text("The UI is not built. Run: cd src/Apps/SimpleSign.TestBench/web && npm ci && npm run build (or npm run dev for hot reload).", "text/plain"));
}

string url = $"http://127.0.0.1:{port}";
app.Lifetime.ApplicationStarted.Register(() =>
{
    Console.WriteLine($"SimpleSign TestBench: {url}");
    if (openBrowser && ui is not null)
    {
        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // No browser available (headless): the URL is printed above.
        }
    }
});

await app.RunAsync();
