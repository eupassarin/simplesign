using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Crypto;

/// <summary>ACT authentication (Authorization, client certificate) and the RFC 3161 TCP transport.</summary>
[Trait("Category", "Unit")]
public sealed class TimestampTransportTests
{
    [Fact]
    public async Task GetTimestampAsync_WithAuthorization_SendsHeaderOnEveryRequest()
    {
        AuthenticationHeaderValue? sent = null;
        var http = new HttpClient(new MockHttpHandler(async request =>
        {
            sent = request.Headers.Authorization;
            byte[] body = await request.Content!.ReadAsByteArrayAsync();
            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(TimestampTestResponseBuilder.CreateForRequest(body)) };
            response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-reply");
            return response;
        }));
        var options = new TimestampOptions(new Uri("https://tsa.example.com/act"))
        {
            Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String("user:secret"u8)),
        };

        byte[] token = await new TimestampClient(http, options).GetTimestampAsync(new byte[] { 1, 2, 3 }, HashAlgorithmName.SHA256);

        token.ShouldNotBeEmpty();
        sent.ShouldNotBeNull();
        sent.Scheme.ShouldBe("Basic");
        http.DefaultRequestHeaders.Authorization.ShouldBeNull("credentials must not leak into the shared client");
    }

    [Fact]
    public async Task GetTimestampAsync_Unauthorized_Throws()
    {
        var http = new HttpClient(new MockHttpHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized))));

        var ex = await Should.ThrowAsync<TimestampException>(() =>
            new TimestampClient(http, "https://tsa.example.com/act").GetTimestampAsync(new byte[] { 1 }, HashAlgorithmName.SHA256));

        ex.Message.ShouldContain("401");
    }

    [Theory]
    [InlineData("tcp://act.example.com:318", true)]
    [InlineData("https://act.example.com", false)]
    public void Options_TcpEndpoint_IsAccepted(string endpoint, bool isTcp)
    {
        var options = new TimestampOptions(new Uri(endpoint));

        options.IsTcp.ShouldBe(isTcp);
        options.NeedsDedicatedClient.ShouldBe(isTcp);
    }

    [Fact]
    public void Options_OtherScheme_Throws() =>
        Should.Throw<ArgumentException>(() => new TimestampOptions(new Uri("ftp://act.example.com")));

    [Fact]
    public void Options_WithCredentialsOrCertificate_NeedDedicatedClient()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var basic = new TimestampOptions(new Uri("https://act.example.com"));

        (basic with { Authorization = new AuthenticationHeaderValue("Bearer", "t") }).NeedsDedicatedClient.ShouldBeTrue();
        (basic with { ClientCertificate = cert }).NeedsDedicatedClient.ShouldBeTrue();
        basic.NeedsDedicatedClient.ShouldBeFalse();
    }

    [Fact]
    public void Create_WithClientCertificate_ReturnsClient()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        var options = new TimestampOptions(new Uri("https://act.example.com")) { ClientCertificate = cert };

        TimestampClient.Create(options, DefaultHttpClientProvider()).ShouldNotBeNull();
    }

    [Theory]
    [InlineData("tcp://127.0.0.1:318")]
    [InlineData("tcp://localhost")]
    [InlineData("tcp://10.0.0.1:318")]
    public void Constructor_TcpToPrivateNetwork_Throws(string endpoint) =>
        Should.Throw<ArgumentException>(() => new TimestampClient(new HttpClient(), endpoint));

    [Fact]
    public async Task SendTcpAsync_FramesRequestAndReadsFinalMessage()
    {
        byte[] request = [0x30, 0x03, 0x02, 0x01, 0x01];
        byte[] reply = [0x30, 0x02, 0x05, 0x00];
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        byte[]? received = null;
        var server = Task.Run(async () =>
        {
            using var socket = await listener.AcceptTcpClientAsync();
            var stream = socket.GetStream();
            byte[] header = new byte[5];
            await stream.ReadExactlyAsync(header);
            int length = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(header);
            received = new byte[length - 1];
            await stream.ReadExactlyAsync(received);
            header[4].ShouldBe((byte)0, "tsaMsg");
            byte[] frame = new byte[5 + reply.Length];
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(frame, reply.Length + 1);
            frame[4] = 5; // finalMsgRep
            reply.CopyTo(frame, 5);
            await stream.WriteAsync(frame);
        });

        byte[] response = await TimestampClient.SendTcpAsync(new Uri($"tcp://127.0.0.1:{port}"), request, CancellationToken.None);
        await server;

        received.ShouldBe(request);
        response.ShouldBe(reply);
    }

    [Fact]
    public async Task SendTcpAsync_ErrorMessage_Throws()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var server = Task.Run(async () =>
        {
            using var socket = await listener.AcceptTcpClientAsync();
            var stream = socket.GetStream();
            byte[] header = new byte[5];
            await stream.ReadExactlyAsync(header);
            await stream.ReadExactlyAsync(new byte[System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(header) - 1]);
            await stream.WriteAsync(new byte[] { 0, 0, 0, 1, 6 }); // errorMsgRep, empty
        });

        await Should.ThrowAsync<TimestampException>(() =>
            TimestampClient.SendTcpAsync(new Uri($"tcp://127.0.0.1:{port}"), [0x30, 0x00], CancellationToken.None));
        await server;
    }

    private static SimpleSign.Core.Http.IHttpClientProvider DefaultHttpClientProvider() => SimpleSign.Core.Http.DefaultHttpClientProvider.Instance;
}
