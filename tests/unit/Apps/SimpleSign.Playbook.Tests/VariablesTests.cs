using Shouldly;
using SimpleSign.Playbook.Runs;

namespace SimpleSign.Playbook.Tests;

[Trait("Category", "Unit")]
public sealed class VariablesTests
{
    [Fact]
    public void Resolve_KnownNames_AreReplaced()
    {
        var variables = new Variables(new Dictionary<string, string> { ["level"] = "B-${var.x}", ["x"] = "LT" }, _ => null);
        variables.Set("out", "/tmp/step");

        variables.Resolve("${out}/signed.pdf at ${var.level}").ShouldBe("/tmp/step/signed.pdf at B-LT");
    }

    [Fact]
    public void Resolve_Environment_IsRead() =>
        new Variables(null, name => name == "HOME" ? "/home/me" : null).Resolve("${env.HOME}").ShouldBe("/home/me");

    [Fact]
    public void Resolve_DoubleDollar_IsLiteral() =>
        new Variables(null, _ => null).Resolve("$${out}").ShouldBe("${out}");

    [Theory]
    [InlineData("${nope}")]
    [InlineData("${env.NOT_SET}")]
    [InlineData("${out")]
    public void Resolve_UnknownOrBroken_Throws(string text) =>
        Should.Throw<VariableException>(() => new Variables(null, _ => null).Resolve(text));

    [Fact]
    public void Resolve_SelfReference_Throws() =>
        Should.Throw<VariableException>(() => new Variables(new Dictionary<string, string> { ["a"] = "${var.a}" }, _ => null).Resolve("${var.a}"));

    [Fact]
    public void Fork_StepValues_DoNotLeak()
    {
        var run = new Variables(null, _ => null);
        run.Set("run", "/r");
        var step = run.Fork();
        step.Set("cert.path", "/r/a.pfx");

        step.Resolve("${run} ${cert.path}").ShouldBe("/r /r/a.pfx");
        Should.Throw<VariableException>(() => run.Resolve("${cert.path}"));
    }
}
