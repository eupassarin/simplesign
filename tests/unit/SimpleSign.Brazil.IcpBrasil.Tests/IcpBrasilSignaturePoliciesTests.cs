using System.Formats.Asn1;
using Shouldly;

namespace SimpleSign.Brazil.IcpBrasil.Tests;

/// <summary>The embedded ICP-Brasil LPA (CAdES and PAdES) and PA parsing.</summary>
[Trait("Category", "Unit")]
public sealed class IcpBrasilSignaturePoliciesTests
{
    private static readonly DateTimeOffset Nov2026 = new(2026, 11, 4, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void All_ContainsEveryLpaEntry()
    {
        IcpBrasilSignaturePolicies.All.Count.ShouldBe(100);
        IcpBrasilSignaturePolicies.All.ShouldAllBe(p => p.PolicyHash.Length == 20 || p.PolicyHash.Length == 32);
    }

    [Theory]
    [InlineData(IcpBrasilPolicy.AdRb, IcpBrasilPolicyFormat.Pades, "2.16.76.1.7.1.11.1.3", "23E4BE4B9B362172E4EBB0E72B86A133ECE5AAD843D8651C6E38A0BA3F08FC60")]
    [InlineData(IcpBrasilPolicy.AdRt, IcpBrasilPolicyFormat.Pades, "2.16.76.1.7.1.12.1.3", "21D6E8D9F85E5626DC71307337A7CABD6FFEF8D085038746775CF0CE6BA4D3B5")]
    [InlineData(IcpBrasilPolicy.AdRb, IcpBrasilPolicyFormat.Cades, "2.16.76.1.7.1.1.2.4", "1F3C904C44C392FEEF447E21FAA7A04E85D9C0153346320F557B7042AF5DCF13")]
    [InlineData(IcpBrasilPolicy.AdRt, IcpBrasilPolicyFormat.Cades, "2.16.76.1.7.1.2.2.4", "FA59DCA6D9C0E808EB7397B2DE800CCE5B0E4DA2C42E2E5EF2496A2CE6BADCB7")]
    public void Current_ReturnsNewestValidVersion(IcpBrasilPolicy policy, IcpBrasilPolicyFormat format, string oid, string hash)
    {
        var current = IcpBrasilSignaturePolicies.Current(policy, format, Nov2026);

        current.Oid.ShouldBe(oid);
        current.PolicyHashHex.ShouldBe(hash);
        current.HashAlgorithmOid.ShouldBe("2.16.840.1.101.3.4.2.1");
        current.Uri.ShouldStartWith("http://politicas.icpbrasil.gov.br/");
    }

    [Fact]
    public void Current_InThePast_ReturnsVersionInForceThen() =>
        IcpBrasilSignaturePolicies.Current(IcpBrasilPolicy.AdRb, IcpBrasilPolicyFormat.Pades, new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero))
            .Oid.ShouldBe("2.16.76.1.7.1.11.1.1");

    [Fact]
    public void Current_SkipsRevokedVersion()
    {
        // v1.2 (June 2025) was revoked on 2025-07-23, when v1.3 started.
        var aug2025 = new DateTimeOffset(2025, 8, 1, 0, 0, 0, TimeSpan.Zero);

        IcpBrasilSignaturePolicies.Current(IcpBrasilPolicy.AdRb, IcpBrasilPolicyFormat.Pades, aug2025).Oid.ShouldBe("2.16.76.1.7.1.11.1.3");
        IcpBrasilSignaturePolicies.TryFind("2.16.76.1.7.1.11.1.2", out var revoked).ShouldBeTrue();
        revoked.IsValidAt(aug2025).ShouldBeFalse();
    }

    [Fact]
    public void Current_NoneValid_Throws() =>
        Should.Throw<ArgumentException>(() =>
            IcpBrasilSignaturePolicies.Current(IcpBrasilPolicy.AdRb, IcpBrasilPolicyFormat.Pades, new DateTimeOffset(2040, 1, 1, 0, 0, 0, TimeSpan.Zero)));

    [Fact]
    public void RequiresSignatureTimestamp_OnlyAdRbDoesNot()
    {
        IcpBrasilSignaturePolicies.Current(IcpBrasilPolicy.AdRb, IcpBrasilPolicyFormat.Pades, Nov2026).RequiresSignatureTimestamp.ShouldBeFalse();
        IcpBrasilSignaturePolicies.Current(IcpBrasilPolicy.AdRt, IcpBrasilPolicyFormat.Pades, Nov2026).RequiresSignatureTimestamp.ShouldBeTrue();
    }

    [Fact]
    public void FromPolicyDocument_ReadsOidHashAndPeriod()
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier("2.16.840.1.101.3.4.2.1");
            }

            using (w.PushSequence()) // signPolicyInfo
            {
                w.WriteObjectIdentifier("2.16.76.1.7.1.11.1.9");
                w.WriteGeneralizedTime(new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero));
                using (w.PushSequence())
                {
                }

                w.WriteCharacterString(UniversalTagNumber.UTF8String, "test");
                using (w.PushSequence()) // signatureValidationPolicy
                {
                    using (w.PushSequence()) // signingPeriod
                    {
                        w.WriteGeneralizedTime(new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero));
                        w.WriteGeneralizedTime(new DateTimeOffset(2040, 1, 1, 0, 0, 0, TimeSpan.Zero));
                    }
                }
            }

            w.WriteOctetString(new byte[32]);
        }

        var policy = IcpBrasilSignaturePolicies.FromPolicyDocument(w.Encode(), "http://example.test/PA.der");

        policy.Oid.ShouldBe("2.16.76.1.7.1.11.1.9");
        policy.Info.Version.ShouldBe("1.9");
        policy.NotAfter.Year.ShouldBe(2040);
        policy.PolicyHash.Length.ShouldBe(32);
    }

    [Fact]
    public void FromPolicyDocument_Garbage_Throws() =>
        Should.Throw<ArgumentException>(() => IcpBrasilSignaturePolicies.FromPolicyDocument([0x30, 0x00], "x"));
}
