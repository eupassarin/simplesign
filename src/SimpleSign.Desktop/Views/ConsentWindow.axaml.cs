using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using SimpleSign.Desktop.Services;

namespace SimpleSign.Desktop.Views;

/// <summary>Asks the user to approve an agent request; closing the window denies it.</summary>
internal sealed partial class ConsentWindow : Window
{
    public ConsentWindow()
        : this(new ConsentRequest("", "", "", null, false))
    {
    }

    public ConsentWindow(ConsentRequest request)
    {
        AvaloniaXamlLoader.Load(this);
        this.FindControl<TextBlock>("TitleText")!.Text = request.Title;
        this.FindControl<TextBlock>("OriginText")!.Text = request.Origin;
        this.FindControl<TextBlock>("MessageText")!.Text = request.Message;
        this.FindControl<Border>("CertificateBox")!.IsVisible = request.CertificateHolder is not null;
        this.FindControl<TextBlock>("CertificateText")!.Text = request.CertificateHolder;
        var always = this.FindControl<Button>("AlwaysButton")!;
        always.IsVisible = request.OfferRemember;
        always.Click += (_, _) => Finish(ConsentDecision.AllowAlways);
        this.FindControl<Button>("AllowButton")!.Click += (_, _) => Finish(ConsentDecision.AllowOnce);
        this.FindControl<Button>("DenyButton")!.Click += (_, _) => Finish(ConsentDecision.Deny);
    }

    public ConsentDecision Decision { get; private set; } = ConsentDecision.Deny;

    private void Finish(ConsentDecision decision)
    {
        Decision = decision;
        Close();
    }
}
