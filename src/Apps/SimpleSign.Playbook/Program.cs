using System.Diagnostics;
using SimpleSign.Playbook;

// SimpleSign Playbook: runs a playbook of SimpleSign CLI commands and records the results.
//   dotnet run --project src/Apps/SimpleSign.Playbook                          (http://127.0.0.1:5400, opens the browser)
//   dotnet run --project src/Apps/SimpleSign.Playbook -- --workspace ~/my-playbook --no-browser
PlaybookOptions options;
try
{
    options = PlaybookOptions.Parse(args);
}
catch (ArgumentException ex)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}

await using var app = PlaybookApp.Build(options, args);
string url = $"http://127.0.0.1:{options.Port}";
app.Lifetime.ApplicationStarted.Register(() =>
{
    Console.WriteLine($"SimpleSign Playbook: {url}");
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
return 0;
