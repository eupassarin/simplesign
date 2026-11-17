using Shouldly;
using SimpleSign.Core.Signing;
using Xunit;

namespace SimpleSign.Core.Tests.Signing;

[Trait("Category", "Unit")]
public sealed class TimestampExceptionTests
{
    [Fact]
    public void ReasonOf_TokenThatFailsItsOwnChecks_IsTimestampInvalid()
    {
        var invalid = new TimestampException("The token's signature does not verify.", SigningErrorReason.TimestampInvalid);
        var wrapped = new TimestampException("Malformed.", SigningErrorReason.TimestampInvalid, new FormatException());

        TimestampException.ReasonOf(invalid).ShouldBe(SigningErrorReason.TimestampInvalid);
        TimestampException.ReasonOf(wrapped).ShouldBe(SigningErrorReason.TimestampInvalid);
        invalid.Reason.ShouldBe(SigningErrorReason.TimestampInvalid);
    }

    [Fact]
    public void ReasonOf_AnythingElse_IsNetworkFailure()
    {
        TimestampException.ReasonOf(new TimestampException("TSA rejected the request.")).ShouldBe(SigningErrorReason.NetworkFailure);
        TimestampException.ReasonOf(new HttpRequestException("connection refused")).ShouldBe(SigningErrorReason.NetworkFailure);
        TimestampException.ReasonOf(new TaskCanceledException()).ShouldBe(SigningErrorReason.NetworkFailure);
    }
}
