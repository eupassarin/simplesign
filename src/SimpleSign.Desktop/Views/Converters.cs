using Avalonia;
using Avalonia.Data.Converters;
using Avalonia.Media;
using SimpleSign.Desktop.Services;

namespace SimpleSign.Desktop.Views;

internal static class Converters
{
    public static readonly IValueConverter StateBrush = new FuncValueConverter<CheckState, IBrush?>(state => Resource<IBrush>(state switch
    {
        CheckState.Ok => "App.Success",
        CheckState.Warning => "App.Warning",
        CheckState.Failed => "App.Danger",
        _ => "App.Secondary",
    }));

    public static readonly IValueConverter StateIcon = new FuncValueConverter<CheckState, Geometry?>(state => Resource<Geometry>(state switch
    {
        CheckState.Ok => "Icon.Check",
        CheckState.Warning => "Icon.Warning",
        CheckState.Failed => "Icon.Cross",
        _ => "Icon.Timestamp",
    }));

    public static readonly IValueConverter IsOk = new FuncValueConverter<CheckState, bool>(s => s == CheckState.Ok);

    public static readonly IValueConverter IsWarning = new FuncValueConverter<CheckState, bool>(s => s == CheckState.Warning);

    public static readonly IValueConverter IsFailed = new FuncValueConverter<CheckState, bool>(s => s == CheckState.Failed);

    public static readonly IValueConverter IconByKey = new FuncValueConverter<string, Geometry?>(key => key is null ? null : Resource<Geometry>(key));

    public static readonly IValueConverter NotNull = new FuncValueConverter<object?, bool>(v => v is not null && v is not "");

    public static readonly IValueConverter Any = new FuncValueConverter<int, bool>(count => count > 0);

    /// <summary>A brush of the current theme (also usable before a window is shown).</summary>
    public static IBrush? Brush(string key) => Resource<IBrush>(key);

    private static T? Resource<T>(string key) where T : class =>
        Application.Current is { } app && app.TryGetResource(key, app.ActualThemeVariant, out object? value) ? value as T : null;
}
