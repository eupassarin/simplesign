using System.Formats.Asn1;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using SimpleSign.Core.Http;

namespace SimpleSign.Core.Revocation;

/// <summary>
/// Reads a CRL from an <c>ldap://</c> or <c>ldaps://</c> distribution point (RFC 4516 URL, RFC 4511
/// protocol): an anonymous bind, one base-object search for the CRL attribute, then unbind. Read-only,
/// written on the BCL's ASN.1 reader and writer, with a size limit and the outbound host checks.
/// </summary>
internal static class LdapCrlClient
{
    /// <summary>The largest LDAP message accepted: CRLs of large CAs reach tens of megabytes.</summary>
    internal const int MaxMessageBytes = 64 * 1024 * 1024;

    private const string DefaultAttribute = "certificateRevocationList;binary";
    private static readonly Asn1Tag BindRequestTag = new(TagClass.Application, 0, isConstructed: true);
    private static readonly Asn1Tag BindResponseTag = new(TagClass.Application, 1, isConstructed: true);
    private static readonly Asn1Tag UnbindRequestTag = new(TagClass.Application, 2, isConstructed: false);
    private static readonly Asn1Tag SearchRequestTag = new(TagClass.Application, 3, isConstructed: true);
    private static readonly Asn1Tag SearchResultEntryTag = new(TagClass.Application, 4, isConstructed: true);
    private static readonly Asn1Tag SearchResultDoneTag = new(TagClass.Application, 5, isConstructed: true);

    /// <summary>Whether <paramref name="url"/> is an LDAP URL this client can read.</summary>
    internal static bool IsLdapUrl(string url) =>
        url.StartsWith("ldap://", StringComparison.OrdinalIgnoreCase)
        || url.StartsWith("ldaps://", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Downloads the CRL named by <paramref name="url"/>. Returns <see langword="null"/> when the
    /// policy refuses the host, the entry has no CRL, or the server answers with an error.
    /// </summary>
    internal static async Task<byte[]?> GetCrlAsync(
        string url,
        OutboundHttpPolicy policy,
        TimeSpan timeout,
        CancellationToken cancellationToken,
        Func<string, CancellationToken, Task<IPAddress[]>>? resolve = null)
    {
        if (!policy.AllowLdap || !TryParseUrl(url, out var target))
        {
            return null;
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);
        var token = cts.Token;

        IPAddress[] addresses = IPAddress.TryParse(target.Host, out var literal)
            ? [literal]
            : await (resolve ?? Dns.GetHostAddressesAsync)(target.Host, token).ConfigureAwait(false);
        var origin = new Uri($"{(target.Secure ? "ldaps" : "ldap")}://{(target.Host.Contains(':', StringComparison.Ordinal) ? $"[{target.Host}]" : target.Host)}:{target.Port}/");
        var address = addresses.FirstOrDefault(a => !UrlValidator.IsBlockedAddress(target.Host, a, policy, origin));
        if (address is null)
        {
            return null;
        }

        using var client = new TcpClient(address.AddressFamily);
        await client.ConnectAsync(address, target.Port, token).ConfigureAwait(false);
        Stream stream = client.GetStream();
        if (target.Secure)
        {
            var ssl = new SslStream(stream, leaveInnerStreamOpen: false);
            await ssl.AuthenticateAsClientAsync(
                new SslClientAuthenticationOptions { TargetHost = target.Host }, token).ConfigureAwait(false);
            stream = ssl;
        }

        await using (stream.ConfigureAwait(false))
        {
            return await ReadAttributeAsync(stream, target.BaseDn, target.Attribute, token).ConfigureAwait(false);
        }
    }

    /// <summary>The LDAP exchange over an open connection: bind, search, unbind.</summary>
    internal static async Task<byte[]?> ReadAttributeAsync(
        Stream stream, string baseDn, string attribute, CancellationToken cancellationToken)
    {
        await WriteAsync(stream, BindRequest(1), cancellationToken).ConfigureAwait(false);
        var bindResponse = await ReadMessageAsync(stream, cancellationToken).ConfigureAwait(false);
        if (ResultCode(bindResponse, BindResponseTag) != 0)
        {
            return null;
        }

        await WriteAsync(stream, SearchRequest(2, baseDn, attribute), cancellationToken).ConfigureAwait(false);
        byte[]? value = null;
        while (true)
        {
            var message = await ReadMessageAsync(stream, cancellationToken).ConfigureAwait(false);
            var op = ProtocolOp(message, out var opTag);
            if (opTag.HasSameClassAndValue(SearchResultEntryTag))
            {
                value ??= ReadAttributeValue(op, attribute);
            }
            else if (opTag.HasSameClassAndValue(SearchResultDoneTag))
            {
                break;
            }
        }

        await WriteAsync(stream, UnbindRequest(3), cancellationToken).ConfigureAwait(false);
        return value;
    }

    private static byte[] BindRequest(int messageId)
    {
        var writer = new AsnWriter(AsnEncodingRules.BER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(messageId);
            using (writer.PushSequence(BindRequestTag))
            {
                writer.WriteInteger(3);
                writer.WriteOctetString([]);
                writer.WriteOctetString([], new Asn1Tag(TagClass.ContextSpecific, 0));
            }
        }

        return writer.Encode();
    }

    private static byte[] SearchRequest(int messageId, string baseDn, string attribute)
    {
        var writer = new AsnWriter(AsnEncodingRules.BER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(messageId);
            using (writer.PushSequence(SearchRequestTag))
            {
                writer.WriteOctetString(System.Text.Encoding.UTF8.GetBytes(baseDn));
                writer.WriteEnumeratedValue(SearchScope.BaseObject);
                writer.WriteEnumeratedValue(DerefAliases.Never);
                writer.WriteInteger(1);
                writer.WriteInteger(0);
                writer.WriteBoolean(false);
                // (objectClass=*): present filter, [7] IMPLICIT AttributeDescription.
                writer.WriteOctetString("objectClass"u8, new Asn1Tag(TagClass.ContextSpecific, 7));
                using (writer.PushSequence())
                {
                    writer.WriteOctetString(System.Text.Encoding.UTF8.GetBytes(attribute));
                }
            }
        }

        return writer.Encode();
    }

    private static byte[] UnbindRequest(int messageId)
    {
        var writer = new AsnWriter(AsnEncodingRules.BER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(messageId);
            writer.WriteNull(UnbindRequestTag);
        }

        return writer.Encode();
    }

    /// <summary>The protocolOp of an LDAPMessage, after the messageID.</summary>
    private static AsnReader ProtocolOp(byte[] message, out Asn1Tag tag)
    {
        var sequence = new AsnReader(message, AsnEncodingRules.BER).ReadSequence();
        sequence.ReadInteger();
        tag = sequence.PeekTag();
        return new AsnReader(sequence.ReadEncodedValue(), AsnEncodingRules.BER);
    }

    private static long ResultCode(byte[] message, Asn1Tag expected)
    {
        var op = ProtocolOp(message, out var tag);
        if (!tag.HasSameClassAndValue(expected))
        {
            throw new InvalidDataException($"Unexpected LDAP response {tag}.");
        }

        var bytes = op.ReadSequence(expected).ReadEnumeratedBytes().Span;
        long code = 0;
        foreach (byte b in bytes)
        {
            code = (code << 8) | b;
        }

        return code;
    }

    private static byte[]? ReadAttributeValue(AsnReader op, string attribute)
    {
        var entry = op.ReadSequence(SearchResultEntryTag);
        entry.ReadOctetString();
        var attributes = entry.ReadSequence();
        string wanted = BaseName(attribute);
        while (attributes.HasData)
        {
            var partial = attributes.ReadSequence();
            string type = System.Text.Encoding.UTF8.GetString(partial.ReadOctetString());
            var values = partial.ReadSetOf();
            if (string.Equals(BaseName(type), wanted, StringComparison.OrdinalIgnoreCase) && values.HasData)
            {
                return values.ReadOctetString();
            }
        }

        return null;
    }

    private static string BaseName(string attribute) =>
        attribute.Split(';', 2)[0];

    private static async Task WriteAsync(Stream stream, byte[] message, CancellationToken cancellationToken)
    {
        await stream.WriteAsync(message, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reads one BER-framed LDAPMessage (definite length) from the stream.</summary>
    internal static async Task<byte[]> ReadMessageAsync(Stream stream, CancellationToken cancellationToken)
    {
        byte[] head = new byte[2];
        await stream.ReadExactlyAsync(head, cancellationToken).ConfigureAwait(false);
        if (head[0] != 0x30)
        {
            throw new InvalidDataException("An LDAP message must start with a SEQUENCE.");
        }

        int length;
        byte[] lengthBytes = [];
        if (head[1] < 0x80)
        {
            length = head[1];
        }
        else
        {
            int count = head[1] & 0x7F;
            if (count is 0 or > 4)
            {
                throw new InvalidDataException("Unsupported LDAP message length.");
            }

            lengthBytes = new byte[count];
            await stream.ReadExactlyAsync(lengthBytes, cancellationToken).ConfigureAwait(false);
            long value = 0;
            foreach (byte b in lengthBytes)
            {
                value = (value << 8) | b;
            }

            if (value > MaxMessageBytes)
            {
                throw new InvalidDataException($"LDAP message of {value} bytes exceeds the limit of {MaxMessageBytes}.");
            }

            length = (int)value;
        }

        byte[] message = new byte[2 + lengthBytes.Length + length];
        head.CopyTo(message, 0);
        lengthBytes.CopyTo(message, 2);
        await stream.ReadExactlyAsync(message.AsMemory(2 + lengthBytes.Length), cancellationToken).ConfigureAwait(false);
        return message;
    }

    /// <summary>Splits an RFC 4516 URL: <c>ldap://host:port/dn?attribute?scope?filter</c>.</summary>
    internal static bool TryParseUrl(string url, out LdapTarget target)
    {
        target = default;
        if (!IsLdapUrl(url))
        {
            return false;
        }

        bool secure = url.StartsWith("ldaps://", StringComparison.OrdinalIgnoreCase);
        string rest = url[(secure ? 8 : 7)..];
        int slash = rest.IndexOf('/', StringComparison.Ordinal);
        string authority = slash < 0 ? rest : rest[..slash];
        string path = slash < 0 ? string.Empty : rest[(slash + 1)..];
        if (authority.Length == 0)
        {
            return false;
        }

        string host = authority;
        int port = secure ? 636 : 389;
        int colon = authority.LastIndexOf(':');
        if (colon > 0 && !authority.EndsWith(']') && int.TryParse(authority[(colon + 1)..], out int parsedPort))
        {
            host = authority[..colon];
            port = parsedPort;
        }

        host = host.Trim('[', ']');
        string[] parts = path.Split('?');
        string dn = Uri.UnescapeDataString(parts[0]);
        string attribute = parts.Length > 1 && parts[1].Length > 0
            ? Uri.UnescapeDataString(parts[1].Split(',')[0])
            : DefaultAttribute;
        if (dn.Length == 0 || port is <= 0 or > 65535)
        {
            return false;
        }

        target = new LdapTarget(host, port, secure, dn, attribute);
        return true;
    }

    internal readonly record struct LdapTarget(string Host, int Port, bool Secure, string BaseDn, string Attribute);

    private enum SearchScope
    {
        BaseObject = 0,
    }

    private enum DerefAliases
    {
        Never = 0,
    }
}
