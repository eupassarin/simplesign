using System.Diagnostics;
using System.Formats.Asn1;
using System.Net;
using System.Net.Sockets;
using System.Text;
using SimpleSign.Sandbox.Pki;

namespace SimpleSign.Sandbox.Services;

/// <summary>
/// A minimal, read-only LDAPv3 server for CRLs over <c>ldap://</c>: anonymous bind, a base-object
/// search of <c>cn={ca},o=sandbox</c> that returns <c>certificateRevocationList;binary</c> (the CA's
/// CRL, with the CRL failures applied) and unbind. Anything else is answered with an error.
/// </summary>
internal sealed class LdapResponder(SandboxPki pki, SandboxOptions options, RequestLog log, ILogger<LdapResponder> logger) : BackgroundService
{
    private const int MaxMessageBytes = 64 * 1024;
    private static readonly Asn1Tag BindRequest = new(TagClass.Application, 0, true);
    private static readonly Asn1Tag BindResponse = new(TagClass.Application, 1, true);
    private static readonly Asn1Tag UnbindRequest = new(TagClass.Application, 2);
    private static readonly Asn1Tag SearchRequest = new(TagClass.Application, 3, true);
    private static readonly Asn1Tag SearchResultEntry = new(TagClass.Application, 4, true);
    private static readonly Asn1Tag SearchResultDone = new(TagClass.Application, 5, true);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Both loopback families: clients resolving "localhost" may try ::1 first.
        IPAddress[] addresses = options.ListenAnyAddress ? [IPAddress.IPv6Any] : [IPAddress.Loopback, IPAddress.IPv6Loopback];
        var listeners = new List<TcpListener>();
        foreach (var address in addresses)
        {
            var listener = new TcpListener(address, options.ResolvedLdapPort);
            if (address.Equals(IPAddress.IPv6Any))
            {
                listener.Server.DualMode = true;
            }

            try
            {
                listener.Start();
                listeners.Add(listener);
            }
            catch (SocketException ex)
            {
                logger.LogWarning("LDAP: cannot listen on {Address}:{Port} ({Message}).", address, options.ResolvedLdapPort, ex.Message);
            }
        }

        try
        {
            await Task.WhenAll(listeners.Select(l => AcceptAsync(l, stoppingToken)));
        }
        finally
        {
            foreach (var listener in listeners)
            {
                listener.Stop();
                listener.Dispose();
            }
        }
    }

    private async Task AcceptAsync(TcpListener listener, CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await listener.AcceptTcpClientAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            _ = Task.Run(() => ServeAsync(client, stoppingToken), stoppingToken);
        }
    }

    private async Task ServeAsync(TcpClient client, CancellationToken stoppingToken)
    {
        using var connection = client;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        timeout.CancelAfter(TimeSpan.FromMinutes(1));
        var ct = timeout.Token;
        string? peer = (client.Client.RemoteEndPoint as IPEndPoint)?.Address.ToString();
        try
        {
            var stream = client.GetStream();
            while (true)
            {
                byte[] message = await ReadMessageAsync(stream, ct);
                var sequence = new AsnReader(message, AsnEncodingRules.BER).ReadSequence();
                int id = (int)sequence.ReadInteger();
                var tag = sequence.PeekTag();
                if (tag.HasSameClassAndValue(BindRequest))
                {
                    await stream.WriteAsync(Result(id, BindResponse, 0, ""), ct);
                }
                else if (tag.HasSameClassAndValue(SearchRequest))
                {
                    await SearchAsync(stream, id, sequence.ReadSequence(SearchRequest), peer, ct);
                }
                else if (tag.HasSameClassAndValue(UnbindRequest))
                {
                    return;
                }
                else
                {
                    // protocolError, then close.
                    await stream.WriteAsync(Result(id, SearchResultDone, 2, "Only bind, search and unbind are supported."), ct);
                    return;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or AsnContentException or InvalidDataException or OperationCanceledException or SocketException)
        {
            // The client went away or sent garbage: nothing to answer.
        }
    }

    private async Task SearchAsync(NetworkStream stream, int id, AsnReader search, string? peer, CancellationToken ct)
    {
        var watch = Stopwatch.StartNew();
        string baseDn = Encoding.UTF8.GetString(search.ReadOctetString());
        string caId = baseDn.StartsWith("cn=", StringComparison.OrdinalIgnoreCase) && baseDn.EndsWith(",o=sandbox", StringComparison.OrdinalIgnoreCase)
            ? baseDn[3..^",o=sandbox".Length]
            : "";
        var faults = pki.Faults;
        string? fault = faults.Crl == CrlFault.None ? null : faults.Crl == CrlFault.Slow ? $"Slow ({faults.CrlDelayMs} ms)" : faults.Crl.ToString();
        int status;
        if (!pki.Authorities.Any(a => a.Id == caId))
        {
            status = 32;
            await stream.WriteAsync(Result(id, SearchResultDone, status, $"No entry {baseDn}."), ct);
        }
        else if (faults.Crl == CrlFault.Down)
        {
            status = 51;
            await stream.WriteAsync(Result(id, SearchResultDone, status, "Sandbox failure: the CRL server is busy."), ct);
        }
        else
        {
            if (faults.Crl == CrlFault.Slow)
            {
                await Task.Delay(faults.CrlDelayMs, ct);
            }

            byte[] crl = faults.Crl == CrlFault.Slow ? pki.Crl(caId) : pki.Crl(caId, faults.Crl);
            await stream.WriteAsync(Entry(id, baseDn, crl), ct);
            status = 0;
            await stream.WriteAsync(Result(id, SearchResultDone, status, ""), ct);
        }

        log.Add("SEARCH", $"ldap {baseDn}", status, "CRL (LDAP)", fault, watch.ElapsedMilliseconds, peer);
    }

    private static byte[] Entry(int id, string dn, byte[] crl)
    {
        var writer = new AsnWriter(AsnEncodingRules.BER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(id);
            using (writer.PushSequence(SearchResultEntry))
            {
                writer.WriteOctetString(Encoding.UTF8.GetBytes(dn));
                using (writer.PushSequence())
                using (writer.PushSequence())
                {
                    writer.WriteOctetString("certificateRevocationList;binary"u8);
                    using (writer.PushSetOf())
                    {
                        writer.WriteOctetString(crl);
                    }
                }
            }
        }

        return writer.Encode();
    }

    private static byte[] Result(int id, Asn1Tag op, int code, string message)
    {
        var writer = new AsnWriter(AsnEncodingRules.BER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(id);
            using (writer.PushSequence(op))
            {
                writer.WriteEnumeratedValue((LdapResultCode)code);
                writer.WriteOctetString([]);
                writer.WriteOctetString(Encoding.UTF8.GetBytes(message));
            }
        }

        return writer.Encode();
    }

    /// <summary>Reads one BER-framed LDAPMessage (definite length).</summary>
    private static async Task<byte[]> ReadMessageAsync(NetworkStream stream, CancellationToken ct)
    {
        byte[] head = new byte[2];
        await stream.ReadExactlyAsync(head, ct);
        if (head[0] != 0x30)
        {
            throw new InvalidDataException("An LDAP message must start with a SEQUENCE.");
        }

        int length = head[1];
        byte[] lengthBytes = [];
        if (head[1] >= 0x80)
        {
            int count = head[1] & 0x7F;
            if (count is 0 or > 3)
            {
                throw new InvalidDataException("Unsupported LDAP message length.");
            }

            lengthBytes = new byte[count];
            await stream.ReadExactlyAsync(lengthBytes, ct);
            length = lengthBytes.Aggregate(0, (value, b) => (value << 8) | b);
        }

        if (length > MaxMessageBytes)
        {
            throw new InvalidDataException("LDAP message too large.");
        }

        byte[] message = new byte[2 + lengthBytes.Length + length];
        head.CopyTo(message, 0);
        lengthBytes.CopyTo(message, 2);
        await stream.ReadExactlyAsync(message.AsMemory(2 + lengthBytes.Length), ct);
        return message;
    }

    private enum LdapResultCode
    {
        Success = 0,
        ProtocolError = 2,
        NoSuchObject = 32,
        Busy = 51,
    }
}
