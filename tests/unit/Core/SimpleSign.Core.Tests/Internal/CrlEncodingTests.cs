using System.Security.Cryptography;
using System.Text;
using Shouldly;
using SimpleSign.Core.Internal;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Internal;

[Trait("Category", "Unit")]
public sealed class CrlEncodingTests
{
    [Fact]
    public void ToDer_DerCrl_ReturnsTheSameBytes()
    {
        using var pki = new SyntheticPki();
        byte[] der = pki.BuildLeafCrl();

        CrlEncoding.ToDer(der).ShouldBeSameAs(der);
    }

    [Fact]
    public void ToDer_PemCrl_ReturnsItsDer()
    {
        using var pki = new SyntheticPki();
        byte[] der = pki.BuildLeafCrl();

        CrlEncoding.ToDer(Encoding.ASCII.GetBytes(new string(PemEncoding.Write("X509 CRL", der)) + "\n")).ShouldBe(der);
    }

    [Fact]
    public void ToDer_PemWithTextBeforeAndAnotherBlockFirst_ReturnsTheCrlBlock()
    {
        byte[] der = [0x30, 0x03, 0x02, 0x01, 0x01];
        string pem = "Issued by the test CA\n" + new string(PemEncoding.Write("CERTIFICATE", [0x30, 0x00])) + "\n"
            + new string(PemEncoding.Write("X509 CRL", der)) + "\n";

        CrlEncoding.ToDer(Encoding.ASCII.GetBytes(pem)).ShouldBe(der);
    }

    [Fact]
    public void ToDer_PemWithoutCrlBlock_ReturnsTheSameBytes()
    {
        byte[] pem = Encoding.ASCII.GetBytes(new string(PemEncoding.Write("CERTIFICATE", [0x30, 0x00])));

        CrlEncoding.ToDer(pem).ShouldBeSameAs(pem);
    }

    [Fact]
    public void ToDer_NotUtf8_ReturnsTheSameBytes()
    {
        byte[] garbage = [0xFF, 0xFE, 0x00, 0x81];

        CrlEncoding.ToDer(garbage).ShouldBeSameAs(garbage);
    }

    [Fact]
    public void ToDer_NullOrEmpty_ReturnsThem()
    {
        CrlEncoding.ToDer(null).ShouldBeNull();
        CrlEncoding.ToDer([]).ShouldBeEmpty();
    }
}
