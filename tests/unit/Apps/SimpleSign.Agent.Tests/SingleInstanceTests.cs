using Shouldly;
using SimpleSign.Agent.Services;

namespace SimpleSign.Agent.Tests;

[Trait("Category", "Unit")]
public sealed class SingleInstanceTests
{
    [Fact]
    public async Task Acquire_SecondLaunch_AsksTheFirstToShowItsWindow()
    {
        string name = "simplesign-agent-test-" + Guid.NewGuid().ToString("N")[..12];
        using var first = SingleInstance.Acquire(name);
        first.ShouldNotBeNull();
        var shown = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        first.ShowRequested += (_, _) => shown.TrySetResult();

        // The first instance starts listening on another thread: try until it answers.
        SingleInstance? second = first;
        for (int i = 0; i < 100 && second is not null; i++)
        {
            await Task.Delay(20);
            second = SingleInstance.Acquire(name);
            second?.Dispose();
        }

        second.ShouldBeNull();
        await shown.Task.WaitAsync(TimeSpan.FromSeconds(10));
    }

    [Fact]
    public void Acquire_AfterTheFirstExits_Succeeds()
    {
        string name = "simplesign-agent-test-" + Guid.NewGuid().ToString("N")[..12];
        SingleInstance.Acquire(name).ShouldNotBeNull().Dispose();

        using var again = SingleInstance.Acquire(name);

        again.ShouldNotBeNull();
    }
}
