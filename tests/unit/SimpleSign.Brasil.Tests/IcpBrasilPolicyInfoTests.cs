using Shouldly;
using SimpleSign.Brasil.IcpBrasil;

namespace SimpleSign.Brasil.Tests;

/// <summary>Signature policy OIDs 2.16.76.1.7.1.{n}.{version} as listed in ADE-ICP-04.01.</summary>
[Trait("Category", "Unit")]
public sealed class IcpBrasilPolicyInfoTests
{
    [Theory]
    [InlineData("2.16.76.1.7.1.1.2.3", IcpBrasilPolicy.AdRb, IcpBrasilPolicyFormat.Cades, "2.3")]
    [InlineData("2.16.76.1.7.1.2.2.3", IcpBrasilPolicy.AdRt, IcpBrasilPolicyFormat.Cades, "2.3")]
    [InlineData("2.16.76.1.7.1.3.2.3", IcpBrasilPolicy.AdRv, IcpBrasilPolicyFormat.Cades, "2.3")]
    [InlineData("2.16.76.1.7.1.4.2.3", IcpBrasilPolicy.AdRc, IcpBrasilPolicyFormat.Cades, "2.3")]
    [InlineData("2.16.76.1.7.1.5.2.4", IcpBrasilPolicy.AdRa, IcpBrasilPolicyFormat.Cades, "2.4")]
    [InlineData("2.16.76.1.7.1.6.2.4", IcpBrasilPolicy.AdRb, IcpBrasilPolicyFormat.Xades, "2.4")]
    [InlineData("2.16.76.1.7.1.8.2.1", IcpBrasilPolicy.AdRv, IcpBrasilPolicyFormat.Xades, "2.1")]
    [InlineData("2.16.76.1.7.1.10.2.4", IcpBrasilPolicy.AdRa, IcpBrasilPolicyFormat.Xades, "2.4")]
    [InlineData("2.16.76.1.7.1.11.1.1", IcpBrasilPolicy.AdRb, IcpBrasilPolicyFormat.Pades, "1.1")]
    [InlineData("2.16.76.1.7.1.12.1.1", IcpBrasilPolicy.AdRt, IcpBrasilPolicyFormat.Pades, "1.1")]
    [InlineData("2.16.76.1.7.1.13.1.2", IcpBrasilPolicy.AdRc, IcpBrasilPolicyFormat.Pades, "1.2")]
    [InlineData("2.16.76.1.7.1.14.1.2", IcpBrasilPolicy.AdRa, IcpBrasilPolicyFormat.Pades, "1.2")]
    public void TryParse_OfficialOid_ReturnsPolicyFormatAndVersion(
        string oid, IcpBrasilPolicy policy, IcpBrasilPolicyFormat format, string version)
    {
        IcpBrasilPolicyInfo.TryParse(oid, out var info).ShouldBeTrue();
        info.ShouldBe(new IcpBrasilPolicyInfo(oid, policy, format, version));
    }

    [Fact]
    public void TryParse_PolicyArcWithoutVersion_HasNullVersion()
    {
        IcpBrasilPolicyInfo.TryParse("2.16.76.1.7.1.12", out var info).ShouldBeTrue();
        info!.Version.ShouldBeNull();
        info.Policy.ShouldBe(IcpBrasilPolicy.AdRt);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("2.16.76.1.7.1.15.1.1")]  // no such policy
    [InlineData("2.16.76.1.7.1.0.1.1")]
    [InlineData("2.16.76.1.7.1.x.1")]
    [InlineData("2.16.76.1.7.1.1..1")]
    [InlineData("2.16.76.1.2.3.126")]     // a certificate policy, not a signature policy
    [InlineData("1.2.3.4")]
    public void TryParse_NotAnIcpBrasilSignaturePolicy_ReturnsFalse(string? oid)
    {
        IcpBrasilPolicyInfo.TryParse(oid, out var info).ShouldBeFalse();
        info.ShouldBeNull();
    }
}
