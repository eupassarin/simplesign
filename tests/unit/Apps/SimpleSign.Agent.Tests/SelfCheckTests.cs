using Shouldly;
using SimpleSign.Agent.Services;

namespace SimpleSign.Agent.Tests;

[Trait("Category", "Unit")]
public sealed class SelfCheckTests
{
    [Fact]
    public async Task Run_EverythingInPlace_ReportsOk()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        int code = await SelfCheck.RunAsync(output, error);

        error.ToString().ShouldBeEmpty();
        code.ShouldBe(0);
        output.ToString().ShouldContain("self-check: ok");
    }
}
