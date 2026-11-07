using System.Text.Json.Serialization;
using Microsoft.Extensions.FileProviders;
using SimpleSign.Playbook.Endpoints;
using SimpleSign.Playbook.Runs;
using SimpleSign.Playbook.Workspaces;

namespace SimpleSign.Playbook;

/// <summary>Builds the Playbook web app: the API and the UI, on 127.0.0.1.</summary>
public static class PlaybookApp
{
    /// <summary>Builds the app (not started).</summary>
    public static WebApplication Build(PlaybookOptions options, string[]? args = null, IProcessRunner? processes = null, Func<Uri, ISandboxClient>? sandboxFactory = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = args ?? [], ContentRootPath = AppContext.BaseDirectory });
        builder.WebHost.ConfigureKestrel(o =>
        {
            o.ListenLocalhost(options.Port);
            o.Limits.MaxRequestBodySize = 256L * 1024 * 1024;
        });
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        builder.Logging.AddFilter("Microsoft.Hosting.Lifetime", LogLevel.Information);
        builder.Services.ConfigureHttpJsonOptions(o =>
        {
            o.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
            o.SerializerOptions.TypeInfoResolverChain.Insert(0, ApiJson.Default);
        });

        var settings = new AppSettingsStore(options.SettingsDirectory);
        var state = new WorkspaceState(settings);
        if (options.Workspace is not null)
        {
            state.Open(options.Workspace);
        }

        var runner = processes ?? new ProcessRunner();
        var factory = sandboxFactory ?? (url => new SandboxClient(url));
        builder.Services.AddSingleton(options);
        builder.Services.AddSingleton(settings);
        builder.Services.AddSingleton(state);
        builder.Services.AddSingleton(runner);
        builder.Services.AddSingleton(factory);
        builder.Services.AddSingleton(new PlaybookRunner(runner, factory));
        builder.Services.AddSingleton<RunService>();

        var app = builder.Build();
        app.Use(async (context, next) =>
        {
            context.Response.Headers.XContentTypeOptions = "nosniff";
            if (context.Request.Path.StartsWithSegments("/api", StringComparison.Ordinal))
            {
                context.Response.Headers.CacheControl = "no-store";
            }

            await next();
        });

        Api.Map(app);
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
            app.MapGet("/", () => Results.Text("The UI is not built. Run: cd src/Apps/SimpleSign.Playbook/web && npm ci && npm run build.", "text/plain"));
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
