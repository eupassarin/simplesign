using Avalonia.Controls;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using SimpleSign.Desktop.Services;

namespace SimpleSign.Desktop.Views;

/// <summary>Dialogs on the UI thread; agent prompts come to the front even when the window is hidden.</summary>
internal sealed class DialogService(Func<Window?> owner) : IDialogService
{
    public Task<string?> OpenFileAsync(string title, params string[] patterns) => OnUi(async () =>
    {
        var files = await Storage().OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = title,
            AllowMultiple = false,
            FileTypeFilter = patterns.Length == 0 || patterns is ["*"]
                ? null
                : [new FilePickerFileType(string.Join(", ", patterns)) { Patterns = patterns }, FilePickerFileTypes.All],
        });
        return files.Count > 0 ? files[0].TryGetLocalPath() : null;
    });

    public Task<string?> SaveFileAsync(string title, string suggestedName) => OnUi(async () =>
    {
        var file = await Storage().SaveFilePickerAsync(new FilePickerSaveOptions { Title = title, SuggestedFileName = suggestedName });
        return file?.TryGetLocalPath();
    });

    public Task<string?> PickFolderAsync(string title) => OnUi(async () =>
    {
        var folders = await Storage().OpenFolderPickerAsync(new FolderPickerOpenOptions { Title = title });
        return folders.Count > 0 ? folders[0].TryGetLocalPath() : null;
    });

    public Task<string?> AskSecretAsync(string title, string message, string confirmText) => OnUi(async () =>
    {
        var dialog = new PromptWindow(title, message, confirmText);
        return await Show(dialog, () => dialog.Result);
    });

    public Task<ConsentDecision> AskConsentAsync(ConsentRequest request) => OnUi(async () =>
    {
        var dialog = new ConsentWindow(request);
        return await Show(dialog, () => dialog.Decision);
    });

    public Task ShowMessageAsync(string title, string message) => OnUi(async () =>
    {
        var dialog = new PromptWindow(title, message, "OK", askSecret: false);
        await Show(dialog, () => dialog.Result);
        return true;
    });

    private async Task<T> Show<T>(Window dialog, Func<T> result)
    {
        if (owner() is { IsVisible: true } window)
        {
            await dialog.ShowDialog(window);
        }
        else
        {
            // The app is in the menu bar: show the prompt on its own, on top of the browser.
            dialog.Topmost = true;
            dialog.WindowStartupLocation = WindowStartupLocation.CenterScreen;
            var closed = new TaskCompletionSource();
            dialog.Closed += (_, _) => closed.TrySetResult();
            dialog.Show();
            dialog.Activate();
            await closed.Task;
        }

        return result();
    }

    private IStorageProvider Storage() =>
        (owner() ?? throw new InvalidOperationException("No window to show the picker on.")).StorageProvider;

    private static Task<T> OnUi<T>(Func<Task<T>> action) =>
        Dispatcher.UIThread.CheckAccess() ? action() : Dispatcher.UIThread.InvokeAsync(action);
}
