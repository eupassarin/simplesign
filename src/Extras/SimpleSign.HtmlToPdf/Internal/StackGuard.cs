// Licensed to SimpleSign under the MIT License.

using System.Runtime.CompilerServices;

namespace SimpleSign.HtmlToPdf.Internal;

/// <summary>
/// Keeps deep recursion (layout of deeply nested boxes) from overflowing the thread's stack.
/// </summary>
/// <remarks>
/// Layout recurses once or more per nesting level, and the frames are large, so a few hundred
/// levels exhaust a small stack: secondary threads get 512 KiB on macOS with .NET 8. A stack
/// overflow kills the process and cannot be caught, so recursive methods call
/// <see cref="HasSufficientStack"/> first and, when the stack runs low, continue on a thread-pool
/// thread with a fresh stack via <see cref="RunOnEmptyStack{TState}"/> (the same technique
/// <c>System.Text.RegularExpressions</c> uses). The caller blocks while the work runs, so the
/// layout state is never touched by two threads at once.
/// </remarks>
internal static class StackGuard
{
    /// <summary>Gets a value indicating whether enough stack remains to recurse further on this thread.</summary>
    public static bool HasSufficientStack => RuntimeHelpers.TryEnsureSufficientExecutionStack();

    /// <summary>Runs <paramref name="action"/> on a thread-pool thread and waits for it, rethrowing its exception.</summary>
    /// <typeparam name="TState">Type of the state handed to the action.</typeparam>
    /// <param name="action">The work to run.</param>
    /// <param name="state">State for <paramref name="action"/>.</param>
    public static void RunOnEmptyStack<TState>(Action<TState> action, TState state) =>
        // The continuation keeps the wait from inlining the task back onto this (exhausted) stack.
        Task.Run(() => action(state))
            .ContinueWith(t => t.GetAwaiter().GetResult(), CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default)
            .GetAwaiter()
            .GetResult();
}
