using Shouldly;
using SimpleSign.Cli.Commands;

namespace SimpleSign.Cli.Tests;

/// <summary>Validation of the <c>sign</c> options that anchor the stamp to a text (<c>--anchor</c>…).</summary>
[Trait("Category", "Unit")]
public sealed class SignAnchorOptionsTests : IDisposable
{
    private readonly string _pdf = Path.GetTempFileName();
    private readonly string _pfx = Path.GetTempFileName();

    [Fact]
    public void Validate_Anchor_IsAccepted() =>
        Settings(true, "Contratante", "0,30", 1, null, ignoreCase: true).Validate().Successful.ShouldBeTrue();

    [Theory]
    [InlineData(false, "Contratante", null, null, null, "require --visible")]
    [InlineData(true, null, "0,30", null, null, "require --anchor")]
    [InlineData(true, " ", null, null, null, "needs a text")]
    [InlineData(true, "Contratante", "30", null, null, "X,Y in points")]
    [InlineData(true, "Contratante", null, 0, null, "not 0")]
    [InlineData(true, "Contratante", null, null, 2, "cannot go with --page")]
    public void Validate_BadAnchor_IsRejected(bool visible, string? anchor, string? offset, int? occurrence, int? page, string message)
    {
        var result = Settings(visible, anchor, offset, occurrence, page).Validate();

        result.Successful.ShouldBeFalse();
        result.Message.ShouldNotBeNull().ShouldContain(message);
    }

    public void Dispose()
    {
        File.Delete(_pdf);
        File.Delete(_pfx);
    }

    private SignCommand.Settings Settings(bool visible, string? anchor, string? offset, int? occurrence, int? page, bool ignoreCase = false) => new()
    {
        InputPath = _pdf,
        CertPath = _pfx,
        Password = "x",
        Visible = visible,
        Anchor = anchor,
        AnchorOffset = offset,
        AnchorOccurrence = occurrence,
        AnchorIgnoreCase = ignoreCase,
        Page = page,
    };
}
