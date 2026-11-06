using System.Formats.Asn1;
using System.Net;
using System.Net.Sockets;
using Shouldly;
using SimpleSign.Core.Http;
using SimpleSign.Core.Revocation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Revocation;

[Trait("Category", "Unit")]
public sealed class LdapCrlClientTests
{
    [Theory]
    [InlineData("ldap://ldap.ca.example/cn=CA%20Sub,o=Example,c=PE?certificateRevocationList;binary",
        "ldap.ca.example", 389, false, "cn=CA Sub,o=Example,c=PE", "certificateRevocationList;binary")]
    [InlineData("ldaps://ldap.ca.example:6360/cn=CA,c=PE",
        "ldap.ca.example", 6360, true, "cn=CA,c=PE", "certificateRevocationList;binary")]
    [InlineData("LDAP://10.0.0.1/cn=CA?authorityRevocationList;binary?base?objectClass=*",
        "10.0.0.1", 389, false, "cn=CA", "authorityRevocationList;binary")]
    public void TryParseUrl_ValidUrl_SplitsTheParts(string url, string host, int port, bool secure, string dn, string attribute)
    {
        LdapCrlClient.TryParseUrl(url, out var target).ShouldBeTrue();

        target.ShouldBe(new LdapCrlClient.LdapTarget(host, port, secure, dn, attribute));
    }

    [Theory]
    [InlineData("http://ca.example/crl")]
    [InlineData("ldap:///cn=CA")]
    [InlineData("ldap://host/")]
    public void TryParseUrl_InvalidUrl_ReturnsFalse(string url) =>
        LdapCrlClient.TryParseUrl(url, out _).ShouldBeFalse();

    [Fact]
    public async Task ReadAttributeAsync_ServerReturnsCrl_ReturnsTheValue()
    {
        using var pki = new SyntheticPki();
        byte[] crl = pki.BuildLeafCrl();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var server = ServeOnceAsync(listener, "certificateRevocationList;binary", crl, resultCode: 0);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
        byte[]? value = await LdapCrlClient.ReadAttributeAsync(
            client.GetStream(), "cn=CA,c=PE", "certificateRevocationList;binary", CancellationToken.None);

        value.ShouldBe(crl);
        (await server).ShouldBe("cn=CA,c=PE");
    }

    [Fact]
    public async Task ReadAttributeAsync_BindRefused_ReturnsNull()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var server = ServeOnceAsync(listener, "certificateRevocationList;binary", [1], resultCode: 49);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
        byte[]? value = await LdapCrlClient.ReadAttributeAsync(
            client.GetStream(), "cn=CA", "certificateRevocationList;binary", CancellationToken.None);

        value.ShouldBeNull();
        await server;
    }

    [Fact]
    public async Task GetCrlAsync_LdapNotAllowed_ReturnsNullWithoutConnecting()
    {
        bool resolved = false;
        byte[]? crl = await LdapCrlClient.GetCrlAsync(
            "ldap://ldap.ca.example/cn=CA", OutboundHttpPolicy.Default, TimeSpan.FromSeconds(5), CancellationToken.None,
            (_, _) => { resolved = true; return Task.FromResult(Array.Empty<IPAddress>()); });

        crl.ShouldBeNull();
        resolved.ShouldBeFalse();
    }

    [Fact]
    public async Task GetCrlAsync_HostResolvesToPrivateAddress_ReturnsNull()
    {
        var policy = new OutboundHttpPolicy { AllowLdap = true };

        byte[]? crl = await LdapCrlClient.GetCrlAsync(
            "ldap://ldap.ca.example/cn=CA", policy, TimeSpan.FromSeconds(5), CancellationToken.None,
            (_, _) => Task.FromResult(new[] { IPAddress.Parse("10.1.2.3") }));

        crl.ShouldBeNull();
    }

    [Fact]
    public async Task GetCrlAsync_Loopback_ReturnsNull()
    {
        var policy = new OutboundHttpPolicy { AllowLdap = true };

        byte[]? crl = await LdapCrlClient.GetCrlAsync(
            "ldap://127.0.0.1/cn=CA", policy, TimeSpan.FromSeconds(5), CancellationToken.None);

        crl.ShouldBeNull();
    }

    /// <summary>A one-connection LDAP server: answers the bind, then the search with one entry.</summary>
    private static async Task<string?> ServeOnceAsync(TcpListener listener, string attribute, byte[] value, int resultCode)
    {
        using var connection = await listener.AcceptTcpClientAsync();
        var stream = connection.GetStream();
        await LdapCrlClient.ReadMessageAsync(stream, CancellationToken.None);
        await stream.WriteAsync(Result(1, 1, resultCode));
        if (resultCode != 0)
        {
            return null;
        }

        byte[] search = await LdapCrlClient.ReadMessageAsync(stream, CancellationToken.None);
        var request = new AsnReader(search, AsnEncodingRules.BER).ReadSequence();
        request.ReadInteger();
        string baseDn = System.Text.Encoding.UTF8.GetString(
            request.ReadSequence(new Asn1Tag(TagClass.Application, 3, true)).ReadOctetString());

        var entry = new AsnWriter(AsnEncodingRules.BER);
        using (entry.PushSequence())
        {
            entry.WriteInteger(2);
            using (entry.PushSequence(new Asn1Tag(TagClass.Application, 4, true)))
            {
                entry.WriteOctetString(System.Text.Encoding.UTF8.GetBytes(baseDn));
                using (entry.PushSequence())
                using (entry.PushSequence())
                {
                    entry.WriteOctetString(System.Text.Encoding.UTF8.GetBytes(attribute));
                    using (entry.PushSetOf())
                    {
                        entry.WriteOctetString(value);
                    }
                }
            }
        }

        await stream.WriteAsync(entry.Encode());
        await stream.WriteAsync(Result(2, 5, 0));
        await LdapCrlClient.ReadMessageAsync(stream, CancellationToken.None);
        return baseDn;
    }

    private static byte[] Result(int messageId, int application, int code)
    {
        var writer = new AsnWriter(AsnEncodingRules.BER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(messageId);
            using (writer.PushSequence(new Asn1Tag(TagClass.Application, application, true)))
            {
                writer.WriteEnumeratedValue((ResultCode)code);
                writer.WriteOctetString([]);
                writer.WriteOctetString([]);
            }
        }

        return writer.Encode();
    }

    private enum ResultCode
    {
        Success = 0,
        InvalidCredentials = 49,
    }
}
