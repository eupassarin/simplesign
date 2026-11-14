using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Headless.XUnit;
using Avalonia.Styling;
using Avalonia.Threading;
using Avalonia.VisualTree;
using Shouldly;
using SimpleSign.Agent.Localization;
using SimpleSign.Agent.Services;
using SimpleSign.Agent.Views;

namespace SimpleSign.Agent.Tests;

/// <summary>
/// Opens the window on the headless platform in every language and both themes, visits every
/// section and panel, and saves each frame as a PNG (bin/…/screenshots) for visual review.
/// </summary>
[Trait("Category", "Unit")]
public sealed class MainWindowTests
{
    private static readonly string s_shots = Path.Combine(AppContext.BaseDirectory, "screenshots");

    [AvaloniaTheory]
    [InlineData("en-US", "light")]
    [InlineData("pt-BR", "dark")]
    [InlineData("es-ES", "light")]
    public async Task EverySectionAndPanel_Renders(string language, string theme)
    {
        MainWindow.Animate = false;
        Directory.CreateDirectory(s_shots);
        using var first = Fixtures.RsaCertificate("CN=Maria Fernanda Oliveira, O=ICP-Brasil, C=BR");
        using var second = Fixtures.EcdsaCertificate();
        using var expiring = Fixtures.RsaCertificate("CN=Empresa Exemplo Ltda, C=BR", validDays: 12);
        IReadOnlyList<CertificateEntry> entries =
        [
            new(CertificateSourceKind.Store, first),
            new(CertificateSourceKind.File, second, FilePath: "beltrana.pfx"),
            new(CertificateSourceKind.Store, expiring),
        ];
        var services = Fixtures.ServicesWithTrust(null, TrustFrameworkCatalog.IcpBrasil);
        services.Settings.Current.AgentPort = Fixtures.FreePort();
        services.Settings.Current.AllowedOrigins.Add("https://portal.example.com");
        services.Settings.Current.BlockedOrigins.Add("https://ads.example.net");
        await using var controller = new AgentController(services, _ => Task.FromResult(entries));
        await controller.StartAsync();
        controller.Server.Origins.Allow("https://intranet.example.org:8443", permanently: false);
        services.Log.Add("Agent", "https://portal.example.com: listed 3 certificate(s)");
        services.Log.Add("Agent", "https://evil.example.com: access refused", isError: true);

        L.Use(language);
        Application.Current!.RequestedThemeVariant = theme == "dark" ? ThemeVariant.Dark : ThemeVariant.Light;
        var window = new MainWindow(controller);
        window.Show();
        Settle(() => window.Inventory is not null);
        window.Inventory!.Certificates.Count.ShouldBe(3);

        foreach (string section in new[] { MainWindow.Overview, MainWindow.Sites, MainWindow.Activity, MainWindow.Test, MainWindow.Documentation })
        {
            window.Navigate(section);
            Capture(window, $"{language}-{theme}-{section}");
            window.Section.ShouldBe(section);
        }

        foreach (string topic in SimpleSign.Agent.Docs.DocLibrary.Topics)
        {
            window.Navigate(MainWindow.Documentation, topic);
            Capture(window, $"{language}-{theme}-docs-{topic}");
        }

        window.Navigate(MainWindow.Overview);
        foreach (string sheet in new[] { MainWindow.SettingsSheet, MainWindow.AboutSheet })
        {
            window.OpenSheet(sheet);
            Capture(window, $"{language}-{theme}-{sheet}");
        }

        window.CloseSheet();
        window.GetVisualDescendants().OfType<TextBlock>().ShouldContain(t => t.Text == L.T("overview.running.title"));
        window.Close();
        L.Use(L.English);
        // Drain the jobs the language change posted while the certificates above are still alive.
        Dispatcher.UIThread.RunJobs();
    }

    /// <summary>
    /// A language change after the window closed must not rebuild its pages: unsubscribing does not cancel a job
    /// already posted, and a page rebuilt then reads certificates whose owner may have released them — which is how
    /// the Overview came to call Thumbprint on a disposed certificate.
    /// </summary>
    [AvaloniaFact]
    public async Task LanguageChangeAfterTheWindowClosed_DoesNotRebuildIt()
    {
        MainWindow.Animate = false;
        L.Use(L.English);
        using var certificate = Fixtures.RsaCertificate();
        IReadOnlyList<CertificateEntry> entries = [new(CertificateSourceKind.Store, certificate)];
        var services = Fixtures.ServicesWithTrust(null, TrustFrameworkCatalog.IcpBrasil);
        services.Settings.Current.AgentPort = Fixtures.FreePort();
        await using var controller = new AgentController(services, _ => Task.FromResult(entries));
        var window = new MainWindow(controller);
        window.Show();
        Settle(() => window.Inventory is not null);
        string english = L.T("overview.certificates.title");
        Has(window, english).ShouldBeTrue();

        window.Close();
        L.Use(L.Portuguese);
        Dispatcher.UIThread.RunJobs();

        try
        {
            // Still the English text: the posted rebuild returned without touching the page or the certificates.
            Has(window, english).ShouldBeTrue();
            Has(window, L.T("overview.certificates.title")).ShouldBeFalse();
        }
        finally
        {
            L.Use(L.English);
            Dispatcher.UIThread.RunJobs();
        }
    }

    [AvaloniaFact]
    public async Task TestPage_RunsTheWholeFlowAndVerifiesTheSignature()
    {
        MainWindow.Animate = false;
        Directory.CreateDirectory(s_shots);
        L.Use(L.Portuguese);
        Application.Current!.RequestedThemeVariant = ThemeVariant.Light;
        using var certificate = Fixtures.RsaCertificate("CN=Maria Fernanda Oliveira, C=BR");
        IReadOnlyList<CertificateEntry> entries = [new(CertificateSourceKind.Store, certificate)];
        var dialogs = new FakeDialogs();
        var services = Fixtures.Services(dialogs);
        services.Settings.Current.AgentPort = Fixtures.FreePort();
        await using var controller = new AgentController(services, _ => Task.FromResult(entries));
        await controller.StartAsync();
        var window = new MainWindow(controller);
        window.Show();
        window.Navigate(MainWindow.Test);

        Click(window, L.T("test.run"));
        Settle(() => Has(window, L.T("test.sign.run")));
        Click(window, L.T("test.sign.run"));
        Settle(() => Has(window, L.T("test.verify.ok")));
        Click(window, L.T("test.details.show"));

        Capture(window, "pt-BR-light-test-done");
        Has(window, L.T("test.verify.ok")).ShouldBeTrue();
        dialogs.Asked.Count.ShouldBe(2);
        services.Signatures.ShouldBe(1);
        window.Close();
        L.Use(L.English);
        Dispatcher.UIThread.RunJobs();
    }

    [AvaloniaFact]
    public void Dialogs_Render()
    {
        L.Use(L.Portuguese);
        Application.Current!.RequestedThemeVariant = ThemeVariant.Light;
        var consent = new ConsentWindow(new ConsentRequest("https://portal.example.com", L.T("consent.sign.title"),
            L.T("consent.sign.message", "https://portal.example.com", "“contrato.pdf”", "Maria Fernanda Oliveira"), "Maria Fernanda Oliveira", OfferRemember: false));
        consent.Show();
        Capture(consent, "dialog-sign");
        consent.Decision.ShouldBe(ConsentDecision.Deny);
        consent.Close();

        var site = new ConsentWindow(new ConsentRequest("https://portal.example.com", L.T("consent.site.title"),
            L.T("consent.site.message", "https://portal.example.com"), null, OfferRemember: true));
        site.Show();
        Capture(site, "dialog-site");
        site.Close();

        var prompt = new PromptWindow(L.T("pin.title"), L.T("pin.message", "SafeNet eToken", "Maria Fernanda Oliveira"), L.T("pin.confirm"));
        prompt.Show();
        Capture(prompt, "dialog-pin");
        prompt.Result.ShouldBeNull();
        prompt.Close();
        L.Use(L.English);
    }

    private static bool Has(Window window, string text) =>
        window.GetVisualDescendants().OfType<TextBlock>().Any(t => t.Text == text);

    /// <summary>Clicks the first enabled button that shows <paramref name="text"/>.</summary>
    private static void Click(Window window, string text)
    {
        Dispatcher.UIThread.RunJobs();
        var button = window.GetVisualDescendants().OfType<Button>()
            .First(b => b.IsEffectivelyEnabled && b.GetVisualDescendants().OfType<TextBlock>().Any(t => t.Text == text));
        button.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
        Dispatcher.UIThread.RunJobs();
    }

    private static void Capture(TopLevel window, string name)
    {
        Dispatcher.UIThread.RunJobs();
        using var frame = window.CaptureRenderedFrame();
        frame.ShouldNotBeNull();
        frame.Save(Path.Combine(s_shots, name + ".png"));
    }

    private static void Settle(Func<bool> done)
    {
        for (int i = 0; i < 200 && !done(); i++)
        {
            Dispatcher.UIThread.RunJobs();
            Thread.Sleep(10);
        }

        Dispatcher.UIThread.RunJobs();
    }
}
