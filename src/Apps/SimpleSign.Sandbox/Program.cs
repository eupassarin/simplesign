using SimpleSign.Sandbox;
using SimpleSign.Sandbox.Pki;

// SimpleSign Sandbox: a test PKI and its services (AIA, CRL, TSA, CSC) on real HTTP endpoints, and the
// admin API that drives them (PKI, revocations, failures, request log). No page of its own: any client uses it
// (the CLI, a playbook, DSS, curl), and the TestBench's Sandbox control is its UI.
//   dotnet run --project src/Apps/SimpleSign.Sandbox                  (http://localhost:5300)
//   dotnet run --project src/Apps/SimpleSign.Sandbox -- --name lab2 --port 5301
//   --public-base-url URL   the URL written into the certificates (fixed when the environment is created)
//   --ephemeral             a new environment in a temporary folder, deleted on exit (CI)
//   --listen-any            listen on every interface (a lab network); --allow-remote-admin opens the admin API too
var options = SandboxOptions.Parse(args);
await using var app = SandboxApp.Build(options, args);
var pki = app.Services.GetRequiredService<SandboxPki>();
string url = $"http://localhost:{options.Port}/";
app.Lifetime.ApplicationStarted.Register(() =>
{
    Console.WriteLine($"SimpleSign Sandbox '{pki.Name}': {url}");
    Console.WriteLine($"  certificates point to {pki.BaseUrl}");
    Console.WriteLine($"  root: {pki.Root.Subject} ({pki.Root.Thumbprint})");
    Console.WriteLine($"  API only: {url}api/info. Its UI is the TestBench: dotnet run --project src/Apps/SimpleSign.TestBench -- --sandbox {url}");
});

await app.RunAsync();
