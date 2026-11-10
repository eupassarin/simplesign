using System.Text.Json.Serialization;
using Microsoft.Extensions.FileProviders;
using SimpleSign.Sandbox.Endpoints;
using SimpleSign.Sandbox.Pki;
using SimpleSign.Sandbox.Services;

namespace SimpleSign.Sandbox;

/// <summary>Builds the Sandbox web app: the PKI of the environment, its services, the admin API and the UI.</summary>
public static class SandboxApp
{
    /// <summary>Builds the app for <paramref name="options"/> (not started).</summary>
    public static WebApplication Build(SandboxOptions options, string[]? args = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        string directory = options.Ephemeral
            ? Path.Combine(Path.GetTempPath(), "simplesign-sandbox-" + Guid.NewGuid().ToString("N")[..12])
            : options.ResolveDataDirectory();

        // The environment is opened before the host: the HTTPS listener needs its TLS certificate.
        SandboxPki pki;
        using (var startupLogging = LoggerFactory.Create(b => b.AddConsole()))
        {
            pki = SandboxPki.Open(directory, options, startupLogging.CreateLogger("SimpleSign.Sandbox"));
        }

        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = args ?? [], ContentRootPath = AppContext.BaseDirectory });
        builder.WebHost.ConfigureKestrel(o =>
        {
            // The server sends its intermediate CA with its certificate, as a real server does: a client
            // that trusts only the Sandbox's root can then build the chain without fetching anything.
            void Https(Microsoft.AspNetCore.Server.Kestrel.Core.ListenOptions listen) => listen.UseHttps(new Microsoft.AspNetCore.Server.Kestrel.Https.HttpsConnectionAdapterOptions
            {
                ServerCertificate = pki.TlsCertificate(),
                ServerCertificateChain = [pki.Intermediate],
            });
            if (options.ListenAnyAddress)
            {
                o.ListenAnyIP(options.Port);
                o.ListenAnyIP(options.ResolvedHttpsPort, Https);
            }
            else
            {
                o.ListenLocalhost(options.Port);
                o.ListenLocalhost(options.ResolvedHttpsPort, Https);
            }
        });
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        builder.Logging.AddFilter("Microsoft.Hosting.Lifetime", LogLevel.Information);
        builder.Services.ConfigureHttpJsonOptions(o => o.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));

        builder.Services.AddSingleton(options);
        builder.Services.AddSingleton(pki);
        builder.Services.AddSingleton<SandboxTrustedLists>();
        builder.Services.AddSingleton<SandboxCsc>();
        builder.Services.AddSingleton<OcspResponder>();
        builder.Services.AddSingleton<RequestLog>();
        builder.Services.AddHostedService<LdapResponder>();

        var app = builder.Build();
        app.Lifetime.ApplicationStopped.Register(pki.Dispose);
        if (options.Ephemeral)
        {
            app.Lifetime.ApplicationStopped.Register(() =>
            {
                try
                {
                    Directory.Delete(directory, recursive: true);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    // A temporary folder left behind is harmless.
                }
            });
        }

        app.Use(async (context, next) =>
        {
            context.Response.Headers.XContentTypeOptions = "nosniff";
            if (context.Request.Path.StartsWithSegments("/api", StringComparison.Ordinal))
            {
                context.Response.Headers.CacheControl = "no-store";
            }

            await next();
        });

        ServiceEndpoints.Map(app);
        AdminEndpoints.Map(app, options);
        MapUi(app);
        return app;
    }

    /// <summary>The UI: the project's web/dist when running from bin/, else the copy published next to the binary.</summary>
    private static void MapUi(WebApplication app)
    {
        string? ui = new[]
        {
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "web", "dist")),
            Path.Combine(AppContext.BaseDirectory, "wwwroot"),
        }.FirstOrDefault(d => File.Exists(Path.Combine(d, "index.html")));
        if (ui is null)
        {
            app.MapGet("/", () => Results.Text("The UI is not built. Run: cd src/Apps/SimpleSign.Sandbox/web && npm ci && npm run build.", "text/plain"));
            return;
        }

        var files = new PhysicalFileProvider(ui);
        app.UseDefaultFiles(new DefaultFilesOptions { FileProvider = files });
        app.UseStaticFiles(new StaticFileOptions { FileProvider = files });
        app.MapFallback(async context =>
        {
            context.Response.ContentType = "text/html; charset=utf-8";
            await context.Response.SendFileAsync(Path.Combine(ui, "index.html"));
        });
    }
}
