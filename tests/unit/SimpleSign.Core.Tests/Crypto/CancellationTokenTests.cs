using System.Security.Cryptography;
using FluentAssertions;
using SimpleSign.Core.Crypto;
using Xunit;

namespace SimpleSign.Core.Tests.Crypto;

/// <summary>
/// Verifies that TimestampClient respects CancellationToken.
/// Uses a pre-canceled token to confirm GetTimestampAsync throws OperationCanceledException.
/// </summary>
[Trait("Category", "Cancellation")]
public sealed class CancellationTokenTests
{
    private static readonly CancellationToken CanceledToken = new(canceled: true);

    [Fact(DisplayName = "TimestampClient.GetTimestampAsync(canceledToken) throws OperationCanceledException")]
    public async Task GetTimestampAsync_CanceledToken_Throws()
    {
        var client = new TimestampClient(new HttpClient(), "http://tsa.example.com/timestamp");
        var data = new ReadOnlyMemory<byte>("timestamp test data"u8.ToArray());

        Func<Task> act = () => client.GetTimestampAsync(data, HashAlgorithmName.SHA256, CanceledToken);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }
}
