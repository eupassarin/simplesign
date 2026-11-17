using Shouldly;
using Xunit;

namespace SimpleSign.Signers.Pkcs11.Tests;

[Trait("Category", "Unit")]
public sealed class Pkcs11KeyProtectionTests
{
    [Theory]
    [InlineData(true, false, true)]
    [InlineData(true, true, false)]
    [InlineData(false, false, false)]
    [InlineData(null, false, false)]
    [InlineData(true, null, false)]
    public void IsConfinedToToken_SensitiveAndNotExtractable_IsTrueOnlyWhenBothAreReported(
        bool? sensitive, bool? extractable, bool expected)
    {
        var protection = new Pkcs11KeyProtection(sensitive, extractable, null, null, null, null);

        protection.IsConfinedToToken.ShouldBe(expected);
    }
}
