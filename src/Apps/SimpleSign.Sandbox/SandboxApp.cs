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
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = args ?? [], ContentRootPath = AppContext.BaseDirectory });
        builder.WebHost.ConfigureKestrel(o =>
        {
            if (options.ListenAnyAddress)
            {
                o.ListenAnyIP(options.Port);
            }
            else
            {
                o.ListenLocalhost(options.Port);
            }
        });
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        builder.Logging.AddFilter("Microsoft.Hosting.Lifetime", LogLevel.Information);
        builder.Services.ConfigureHttpJsonOptions(o => o.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));

        string? directory = options.Ephemeral
            ? Path.Combine(Path.GetTempPath(), "simplesign-sandbox-" + Guid.NewGuid().ToString("N")[..12])
            : options.ResolveDataDirectory();
        builder.Services.AddSingleton(options);
        builder.Services.AddSingleton(services => SandboxPki.Open(directory, options.Name, options.BaseUrl,
            services.GetRequiredService<ILoggerFactory>().CreateLogger("SimpleSign.Sandbox")));
        builder.Services.AddSingleton<SandboxCsc>();
        builder.Services.AddSingleton<TsaServices>();
        builder.Services.AddSingleton<RequestLog>();

        var app = builder.Build();
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

        // Create (or open) the environment before serving, so the first request is not slow.
        _ = app.Services.GetRequiredService<SandboxPki>();

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
