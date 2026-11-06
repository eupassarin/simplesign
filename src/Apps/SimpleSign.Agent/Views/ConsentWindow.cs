using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using SimpleSign.Agent.Localization;
using SimpleSign.Agent.Services;

namespace SimpleSign.Agent.Views;

/// <summary>Asks the user to approve an agent request; closing the window denies it.</summary>
internal sealed class ConsentWindow : Window
{
    public ConsentWindow(ConsentRequest request)
    {
        Title = "SimpleSign Agent";
        Icon = AgentIcons.Window();
        Width = 440;
        SizeToContent = SizeToContent.Height;
        CanResize = false;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;

        bool signing = request.CertificateHolder is not null;
        var deny = Ui.Button(L.T("consent.deny"), null, "outline", () => Finish(ConsentDecision.Deny));
        deny.IsCancel = true;
        var always = request.OfferRemember ? Ui.Button(L.T("consent.always"), null, "outline", () => Finish(ConsentDecision.AllowAlways)) : null;
        var allow = Ui.Button(L.T(signing ? "consent.sign" : "consent.allow"), signing ? Icons.Mark : Icons.Check, "primary", () => Finish(ConsentDecision.AllowOnce));
        allow.IsDefault = true;

        Content = new Border
        {
            Padding = new Thickness(24),
            Child = Ui.Col(16,
                Ui.Row(12,
                    Ui.IconBox(signing ? Icons.Mark : Icons.ShieldCheck, "info", "Info"),
                    Ui.Col(2, Ui.Text(request.Title, "h2"), Ui.Text(request.Origin, "muted small mono"))),
                Ui.Text(request.Message, "wrap relaxed"),
                signing
                    ? new Border { Child = Ui.Row(10, Ui.Icon(Icons.Key, 16, "MutedFg"), Ui.Text(request.CertificateHolder, "strong")) }.Class("well")
                    : null,
                Ui.Row(8, Ui.Icon(Icons.Lock, 13, "MutedFg"), Ui.Text(L.T("consent.hint"), "muted small wrap").With(t => t.MaxWidth = 360)),
                Ui.Row(8, deny, always, allow).With(r => r.HorizontalAlignment = HorizontalAlignment.Right)),
        };
    }

    public ConsentDecision Decision { get; private set; } = ConsentDecision.Deny;

    private void Finish(ConsentDecision decision)
    {
        Decision = decision;
        Close();
    }
}
