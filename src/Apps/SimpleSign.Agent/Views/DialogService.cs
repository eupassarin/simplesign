using Avalonia.Controls;
using Avalonia.Threading;
using SimpleSign.Agent.Services;

namespace SimpleSign.Agent.Views;

/// <summary>Agent prompts on the UI thread, shown on top of the browser.</summary>
internal sealed class DialogService : IDialogService
{
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

    private static async Task<T> Show<T>(Window dialog, Func<T> result)
    {
        dialog.Topmost = true;
        dialog.WindowStartupLocation = WindowStartupLocation.CenterScreen;
        var closed = new TaskCompletionSource();
        dialog.Closed += (_, _) => closed.TrySetResult();
        dialog.Show();
        dialog.Activate();
        await closed.Task;
        return result();
    }

    private static Task<T> OnUi<T>(Func<Task<T>> action) =>
        Dispatcher.UIThread.CheckAccess() ? action() : Dispatcher.UIThread.InvokeAsync(action);
}
