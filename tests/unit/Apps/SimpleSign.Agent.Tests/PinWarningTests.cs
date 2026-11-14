using Avalonia.Controls;
using Avalonia.Headless.XUnit;
using Avalonia.VisualTree;
using Shouldly;
using SimpleSign.Agent.Localization;
using SimpleSign.Agent.Services;
using SimpleSign.Agent.Views;

namespace SimpleSign.Agent.Tests;

/// <summary>
/// The token's PIN flags (<c>CKF_USER_PIN_COUNT_LOW</c>, <c>_FINAL_TRY</c>, <c>_TO_BE_CHANGED</c>) reaching the PIN
/// dialog. Opening a real token session needs a real PKCS#11 device, so the dialog is checked directly.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PinWarningTests
{
    [Fact]
    public void PinWarning_NoFlag_IsNull()
    {
        Token().PinWarning.ShouldBeNull();
        Token().IsPinWarningSevere.ShouldBeFalse();
    }

    [Fact]
    public void PinWarning_FinalTry_WarnsAboutLockingAndIsSevere()
    {
        var token = Token(finalTry: true);

        token.PinWarning.ShouldBe(L.T("pin.warn.finalTry"));
        token.IsPinWarningSevere.ShouldBeTrue();
    }

    [Fact]
    public void PinWarning_CountLow_WarnsWithoutBeingSevere()
    {
        var token = Token(countLow: true);

        token.PinWarning.ShouldBe(L.T("pin.warn.countLow"));
        token.IsPinWarningSevere.ShouldBeFalse();
    }

    [Fact]
    public void PinWarning_MustBeChanged_SaysSo()
    {
        var token = Token(toBeChanged: true);

        token.PinWarning.ShouldBe(L.T("pin.warn.mustChange"));
        token.IsPinWarningSevere.ShouldBeFalse();
    }

    [Fact]
    public void PinWarning_FinalTryAndCountLow_PrefersTheFinalTry() =>
        Token(countLow: true, finalTry: true).PinWarning.ShouldBe(L.T("pin.warn.finalTry"));

    [Fact]
    public void PinWarning_CountLowAndMustBeChanged_PrefersTheChange() =>
        Token(countLow: true, toBeChanged: true).PinWarning.ShouldBe(L.T("pin.warn.mustChange"));

    [AvaloniaFact]
    public void PromptWindow_WithAWarning_ShowsIt()
    {
        var window = new PromptWindow(L.T("pin.title"), L.T("pin.message", "SafeNet eToken", "Maria"), L.T("pin.confirm"),
            L.T("pin.warn.finalTry"), severe: true);
        window.Show();

        Texts(window).ShouldContain(L.T("pin.warn.finalTry"));
        window.Close();
    }

    [AvaloniaFact]
    public void PromptWindow_WithoutAWarning_ShowsNone()
    {
        var window = new PromptWindow(L.T("pin.title"), L.T("pin.message", "SafeNet eToken", "Maria"), L.T("pin.confirm"));
        window.Show();

        Texts(window).ShouldNotContain(L.T("pin.warn.finalTry"));
        window.Close();
    }

    private static IEnumerable<string?> Texts(Window window) =>
        window.GetVisualDescendants().OfType<TextBlock>().Select(t => t.Text);

    private static TokenKey Token(bool countLow = false, bool finalTry = false, bool toBeChanged = false) =>
        new("/usr/lib/libtoken.so", "Test driver", "Token", "0001", "key", HasPinPad: false)
        {
            IsPinCountLow = countLow,
            IsPinFinalTry = finalTry,
            IsPinToBeChanged = toBeChanged,
        };
}
