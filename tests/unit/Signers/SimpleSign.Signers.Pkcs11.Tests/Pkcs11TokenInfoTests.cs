using Shouldly;
using Xunit;

namespace SimpleSign.Signers.Pkcs11.Tests;

[Trait("Category", "Unit")]
public sealed class Pkcs11TokenInfoTests
{
    [Fact]
    public void FromFlags_NoFlags_EveryFlagFalse()
    {
        var token = Token(0);

        token.IsLoginRequired.ShouldBeFalse();
        token.HasProtectedAuthenticationPath.ShouldBeFalse();
        token.IsPinLocked.ShouldBeFalse();
        token.IsPinCountLow.ShouldBeFalse();
        token.IsPinFinalTry.ShouldBeFalse();
        token.IsPinToBeChanged.ShouldBeFalse();
        token.IsUserPinInitialized.ShouldBeFalse();
    }

    [Theory]
    [InlineData(0x4UL, nameof(Pkcs11TokenInfo.IsLoginRequired))]
    [InlineData(0x8UL, nameof(Pkcs11TokenInfo.IsUserPinInitialized))]
    [InlineData(0x100UL, nameof(Pkcs11TokenInfo.HasProtectedAuthenticationPath))]
    [InlineData(0x10000UL, nameof(Pkcs11TokenInfo.IsPinCountLow))]
    [InlineData(0x20000UL, nameof(Pkcs11TokenInfo.IsPinFinalTry))]
    [InlineData(0x40000UL, nameof(Pkcs11TokenInfo.IsPinLocked))]
    [InlineData(0x80000UL, nameof(Pkcs11TokenInfo.IsPinToBeChanged))]
    public void FromFlags_OneFlag_SetsOnlyItsProperty(ulong flag, string property)
    {
        var token = Token(flag);

        Flags(token).Where(f => f.Value).Select(f => f.Key).ShouldBe([property]);
    }

    [Fact]
    public void Constructor_Positional_PinWarningFlagsDefaultToFalse()
    {
        var token = new Pkcs11TokenInfo(1, "t", "m", "model", "sn", true, false, false, []);

        token.IsPinCountLow.ShouldBeFalse();
        token.IsPinFinalTry.ShouldBeFalse();
        token.IsPinToBeChanged.ShouldBeFalse();
        token.IsUserPinInitialized.ShouldBeFalse();
    }

    private static Pkcs11TokenInfo Token(ulong flags) => Pkcs11TokenInfo.FromFlags(1, "label", "maker", "model", "serial", flags, []);

    private static Dictionary<string, bool> Flags(Pkcs11TokenInfo token) => new()
    {
        [nameof(Pkcs11TokenInfo.IsLoginRequired)] = token.IsLoginRequired,
        [nameof(Pkcs11TokenInfo.HasProtectedAuthenticationPath)] = token.HasProtectedAuthenticationPath,
        [nameof(Pkcs11TokenInfo.IsPinLocked)] = token.IsPinLocked,
        [nameof(Pkcs11TokenInfo.IsPinCountLow)] = token.IsPinCountLow,
        [nameof(Pkcs11TokenInfo.IsPinFinalTry)] = token.IsPinFinalTry,
        [nameof(Pkcs11TokenInfo.IsPinToBeChanged)] = token.IsPinToBeChanged,
        [nameof(Pkcs11TokenInfo.IsUserPinInitialized)] = token.IsUserPinInitialized,
    };
}
