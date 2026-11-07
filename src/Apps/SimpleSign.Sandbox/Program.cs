using System.Diagnostics;
using SimpleSign.Sandbox;
using SimpleSign.Sandbox.Pki;

// SimpleSign Sandbox: a test PKI and its services (AIA, CRL, TSA, CSC) on real HTTP endpoints.
//   dotnet run --project src/Apps/SimpleSign.Sandbox                  (http://localhost:5300, opens the browser)
//   dotnet run --project src/Apps/SimpleSign.Sandbox -- --name lab2 --port 5301
//   --public-base-url URL   the URL written into the certificates (fixed when the environment is created)
//   --ephemeral             a new environment in a temporary folder, deleted on exit (CI)
//   --listen-any            listen on every interface (a lab network); --allow-remote-admin opens the admin API too
var options = SandboxOptions.Parse(args);
await using var app = SandboxApp.Build(options, args);
var pki = app.Services.GetRequiredService<SandboxPki>();
string url = $"http://localhost:{options.Port}";
app.Lifetime.ApplicationStarted.Register(() =>
{
    Console.WriteLine($"SimpleSign Sandbox '{pki.Name}': {url}");
    Console.WriteLine($"  certificates point to {pki.BaseUrl}");
    Console.WriteLine($"  root: {pki.Root.Subject} ({pki.Root.Thumbprint})");
    if (options.OpenBrowser)
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
