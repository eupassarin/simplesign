using CommunityToolkit.Mvvm.ComponentModel;
using SimpleSign.Desktop.Services;

namespace SimpleSign.Desktop.ViewModels;

/// <summary>A page of the sidebar.</summary>
internal abstract partial class PageViewModel(AppServices services, string title, string subtitle, string iconKey) : ObservableObject
{
    [ObservableProperty]
    private bool _isBusy;

    [ObservableProperty]
    private string? _errorMessage;

    [ObservableProperty]
    private string? _statusMessage;

    protected AppServices Services { get; } = services;

    public string Title { get; } = title;

    public string Subtitle { get; } = subtitle;

    public string IconKey { get; } = iconKey;

    /// <summary>Runs work with the busy flag and turns exceptions into an error banner.</summary>
    protected async Task RunAsync(Func<Task> work, string? success = null)
    {
        ErrorMessage = null;
        StatusMessage = null;
        IsBusy = true;
        try
        {
            await work();
            StatusMessage = success;
        }
        catch (OperationCanceledException)
        {
            StatusMessage = "Cancelado.";
        }
#pragma warning disable CA1031 // Any library error is shown to the user.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            ErrorMessage = ex.Message;
            Services.Log.Add(Title, ex.Message, isError: true);
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>Called when the page is shown.</summary>
    public virtual Task OnShownAsync() => Task.CompletedTask;
}
