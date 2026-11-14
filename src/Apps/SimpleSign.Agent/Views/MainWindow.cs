using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Threading;
using SimpleSign.Agent.Localization;
using SimpleSign.Agent.Services;
using SimpleSign.Agent.Views.Pages;
using SimpleSign.Agent.Views.Panels;

namespace SimpleSign.Agent.Views;

/// <summary>
/// The agent's window, in the TestBench's layout: one bar at the top (no side menu) that switches
/// between the sections, and Settings and About as panels that slide over them.
/// </summary>
#pragma warning disable CA1001 // _closing is disposed when the window closes.
internal sealed class MainWindow : Window
#pragma warning restore CA1001
{
    public const string Overview = "overview";
    public const string Sites = "sites";
    public const string Activity = "activity";
    public const string Test = "test";
    public const string Documentation = "docs";
    public const string SettingsSheet = "settings";
    public const string AboutSheet = "about";

    private static readonly string[] s_sections = [Overview, Sites, Activity, Test, Documentation];

    private readonly Border _topbar = new Border().Class("topbar");
    private readonly ContentControl _body = new();
    private readonly Panel _overlay = new() { IsVisible = false };
    private readonly Dictionary<string, AgentPage> _pages = new(StringComparer.Ordinal);
    private readonly SettingsPanel _settings;
    private readonly AboutPanel _about;
    private readonly CancellationTokenSource _closing = new();
    private string? _sheet;
    private bool _loadingInventory;

    public MainWindow(AgentController controller)
    {
        Controller = controller;
        _settings = new SettingsPanel(this);
        _about = new AboutPanel(this);
        Title = "SimpleSign Agent";
        Icon = AgentIcons.Window();
        Width = 940;
        Height = 660;
        MinWidth = 840;
        MinHeight = 520;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;

        var grid = new Grid { RowDefinitions = new RowDefinitions("56,*") };
        grid.Children.Add(_topbar.At(0, 0));
        grid.Children.Add(_body.At(0, 1));
        Content = new Panel { Children = { grid, _overlay } };

        Controller.Changed += OnControllerChanged;
        Controller.Services.Log.Added += OnLogAdded;
        Controller.Services.Log.Cleared += OnLogCleared;
        L.Changed += OnLanguageChanged;
        KeyDown += (_, e) =>
        {
            if (e.Key == Key.Escape && _sheet is not null)
            {
                CloseSheet();
                e.Handled = true;
            }
        };
        Closed += (_, _) =>
        {
            Controller.Changed -= OnControllerChanged;
            Controller.Services.Log.Added -= OnLogAdded;
            Controller.Services.Log.Cleared -= OnLogCleared;
            L.Changed -= OnLanguageChanged;
            _closing.Cancel();
            _closing.Dispose();
        };

        RenderTopbar();
        RenderBody();
        _ = RefreshInventoryAsync();
    }

    /// <summary>False in tests: panels open without the slide.</summary>
    public static bool Animate { get; set; } = true;

    public AgentController Controller { get; }

    /// <summary>The section on screen.</summary>
    public string Section { get; private set; } = Overview;

    /// <summary>The certificates and drivers found; null while the first search runs.</summary>
    public CertificateInventory? Inventory { get; private set; }

    /// <summary>Cancelled when the window closes.</summary>
    public CancellationToken Lifetime => _closing.Token;

    /// <summary>Shows a section; for the documentation, <paramref name="topic"/> picks the topic.</summary>
    public void Navigate(string section, string? topic = null)
    {
        Section = section;
        CloseSheet();
        if (section == Documentation && topic is not null)
        {
            ((DocsPage)PageFor(Documentation)).Show(topic);
        }

        RenderTopbar();
        RenderBody();
    }

    public void OpenSheet(string name)
    {
        _sheet = name;
        RenderSheet(Animate);
    }

    public void CloseSheet()
    {
        _sheet = null;
        RenderSheet(false);
    }

    /// <summary>Searches the store and the tokens again.</summary>
    public async Task RefreshInventoryAsync()
    {
        if (_loadingInventory)
        {
            return;
        }

        _loadingInventory = true;
        Inventory = null;
        NotifyPages();
        try
        {
            Inventory = await Controller.InventoryAsync(_closing.Token);
        }
        catch (OperationCanceledException)
        {
            return;
        }
#pragma warning disable CA1031 // A broken driver or store must not take the window down: it is shown as "none found" and logged.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            Controller.Services.Log.Add("Agent", ex.Message, isError: true);
            Inventory = new CertificateInventory([], []);
        }
        finally
        {
            _loadingInventory = false;
        }

        NotifyPages();
    }

    private AgentPage PageFor(string section)
    {
        if (!_pages.TryGetValue(section, out var page))
        {
            page = section switch
            {
                Sites => new SitesPage(this),
                Activity => new ActivityPage(this),
                Test => new TestPage(this),
                Documentation => new DocsPage(this),
                _ => new OverviewPage(this),
            };
            page.Rebuild();
            _pages[section] = page;
        }

        return page;
    }

    private void RenderBody() => _body.Content = PageFor(Section);

    private void RenderTopbar()
    {
        var mark = new Border
        {
            Child = Ui.Icon(Icons.Mark, 18, "PrimaryFg", filled: true).With(i => i.HorizontalAlignment = HorizontalAlignment.Center),
        }.Class("mark");
        var brand = Ui.Row(10, mark, Ui.Col(0, Ui.Text("SimpleSign", "h3"), Ui.Text("Agent", "muted small")));
        var nav = Ui.Segmented([.. s_sections.Select(s => (s, L.T("nav." + s)))], Section, s => Navigate(s));
        nav.VerticalAlignment = VerticalAlignment.Center;
        nav.Margin = new Thickness(16, 0, 0, 0);

        var state = Controller.State;
        var pill = new Border
        {
            Child = Ui.Row(6, Ui.Dot(StateKind(state)), Ui.Text(L.T("state." + state.ToString().ToLowerInvariant()))),
        }.Class("badge").Tip(Controller.StatusText);
        pill.Margin = new Thickness(0, 0, 6, 0);

        var language = L.Languages.First(l => l.Id == L.Language);
        var next = L.Languages[(L.Languages.ToList().FindIndex(l => l.Id == L.Language) + 1) % L.Languages.Count];
        var languageButton = new Button { Content = Ui.Row(5, Ui.Icon(Icons.Globe), Ui.Text(language.Short, "small strong")) }
            .Class("sm").Tip(L.T("topbar.language", language.Label, next.Label));
        languageButton.Click += (_, _) => Appearance.SetLanguage(Controller, next.Id);

        string theme = Controller.Settings.Theme;
        var right = Ui.Row(2,
            pill,
            Ui.IconButton(Icons.Settings, L.T("settings.title"), () => OpenSheet(SettingsSheet)),
            Ui.IconButton(Icons.Info, L.T("about.title"), () => OpenSheet(AboutSheet)),
            languageButton,
            Ui.IconButton(Appearance.ThemeIcon(theme), L.T("topbar.theme", L.T("theme." + theme)), () => Appearance.SetTheme(Controller, Appearance.NextTheme(theme))));

        var grid = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,Auto,*,Auto") };
        grid.Children.Add(brand.At(0));
        grid.Children.Add(nav.At(1));
        grid.Children.Add(right.At(3));
        _topbar.Child = grid;
    }

    private void RenderSheet(bool animate)
    {
        _overlay.Children.Clear();
        if (_sheet is null)
        {
            _overlay.IsVisible = false;
            return;
        }

        bool settings = _sheet == SettingsSheet;
        var scrim = new Border().Class("scrim");
        scrim.PointerPressed += (_, _) => CloseSheet();
        var header = new Border
        {
            Padding = new Thickness(20, 16),
            Child = Ui.Split(
                Ui.Col(2, Ui.Text(L.T(settings ? "settings.title" : "about.title"), "h2"), Ui.Text(L.T(settings ? "settings.subtitle" : "about.subtitle"), "muted small wrap")),
                Ui.IconButton(Icons.X, L.T("common.close"), CloseSheet)),
        };
        var body = new ScrollViewer
        {
            HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Disabled,
            Content = new Border { Padding = new Thickness(20, 16, 20, 24), Child = settings ? _settings.Build() : _about.Build() },
        };
        var dock = new DockPanel();
        DockPanel.SetDock(header, Dock.Top);
        var line = Ui.Line();
        DockPanel.SetDock(line, Dock.Top);
        dock.Children.Add(header);
        dock.Children.Add(line);
        dock.Children.Add(body);
        var sheet = new Border { Width = 460, HorizontalAlignment = HorizontalAlignment.Right, Child = dock }.Class("sheet");

        if (!animate)
        {
            // Set before the controls are attached, so the transitions do not run again on a refresh.
            Open(scrim, sheet);
        }

        _overlay.Children.Add(scrim);
        _overlay.Children.Add(sheet);
        _overlay.IsVisible = true;
        if (animate)
        {
            Dispatcher.UIThread.Post(() => Open(scrim, sheet), DispatcherPriority.Loaded);
        }
    }

    private static void Open(Border scrim, Border sheet)
    {
        scrim.Classes.Add("open");
        sheet.Classes.Add("open");
    }

    private static string StateKind(AgentState state) => state switch
    {
        AgentState.Running => "ok",
        AgentState.Error => "err",
        _ => "warn",
    };

    private void NotifyPages()
    {
        foreach (var page in _pages.Values)
        {
            page.OnAgentChanged();
        }

        if (_sheet is not null)
        {
            RenderSheet(false);
        }
    }

    private void OnControllerChanged(object? sender, EventArgs e) => Dispatcher.UIThread.Post(() =>
    {
        RenderTopbar();
        NotifyPages();
    });

    private void OnLanguageChanged(object? sender, EventArgs e) => Dispatcher.UIThread.Post(() =>
    {
        RenderTopbar();
        foreach (var page in _pages.Values)
        {
            page.Rebuild();
        }

        if (_sheet is not null)
        {
            RenderSheet(false);
        }
    });

    private void OnLogAdded(object? sender, LogEntry entry) => Dispatcher.UIThread.Post(() =>
    {
        foreach (var page in _pages.Values)
        {
            page.OnActivity(entry);
        }
    });

    private void OnLogCleared(object? sender, EventArgs e) => Dispatcher.UIThread.Post(() =>
    {
        foreach (var page in _pages.Values)
        {
            page.OnActivity(null);
        }
    });
}
