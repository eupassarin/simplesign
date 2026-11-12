using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using Shouldly;
using SimpleSign.Core.Signing;
using Xunit;

namespace SimpleSign.Core.Tests.Signing;

/// <summary>The envelope that authenticates the session of a two-phase CAdES or XAdES signature.</summary>
[Trait("Category", "Unit")]
public sealed class DeferredSessionEnvelopeTests
{
    private static readonly byte[] s_key = RandomNumberGenerator.GetBytes(32);
    private static readonly JsonTypeInfo<Session> s_typeInfo =
        (JsonTypeInfo<Session>)JsonSerializerOptions.Default.GetTypeInfo(typeof(Session));

    [Fact]
    public void Unprotect_ProtectedSession_ReturnsTheSession()
    {
        byte[] data = DeferredSessionEnvelope.Protect(new Session { Payload = [1, 2, 3], Level = 2 }, s_typeInfo, "Test", s_key);

        Session session = DeferredSessionEnvelope.Unprotect(data, s_typeInfo, "Test", s_key);

        session.Payload.ShouldBe([1, 2, 3]);
        session.Level.ShouldBe(2);
        using JsonDocument document = JsonDocument.Parse(data);
        document.RootElement.GetProperty("format").GetString().ShouldBe("Test");
        document.RootElement.GetProperty("version").GetInt32().ShouldBe(1);
    }

    [Fact]
    public void Unprotect_SessionChangedAfterItWasProtected_Throws()
    {
        string json = Encoding.UTF8.GetString(DeferredSessionEnvelope.Protect(new Session { Payload = [1], Level = 1 }, s_typeInfo, "Test", s_key));

        byte[] changedValue = Encoding.UTF8.GetBytes(json.Replace("\"Level\":1", "\"Level\":3", StringComparison.Ordinal));
        byte[] addedField = Encoding.UTF8.GetBytes(json.Replace("\"session\":{", "\"session\":{\"Extra\":true,", StringComparison.Ordinal));
        byte[] reformatted = Encoding.UTF8.GetBytes(json.Replace("\"session\":{", "\"session\":{ ", StringComparison.Ordinal));

        Should.Throw<CryptographicException>(() => DeferredSessionEnvelope.Unprotect(changedValue, s_typeInfo, "Test", s_key));
        Should.Throw<CryptographicException>(() => DeferredSessionEnvelope.Unprotect(addedField, s_typeInfo, "Test", s_key));
        Should.Throw<CryptographicException>(() => DeferredSessionEnvelope.Unprotect(reformatted, s_typeInfo, "Test", s_key));
    }

    [Fact]
    public void Unprotect_AnotherKey_Throws()
    {
        byte[] data = DeferredSessionEnvelope.Protect(new Session { Payload = [1] }, s_typeInfo, "Test", s_key);

        Should.Throw<CryptographicException>(() => DeferredSessionEnvelope.Unprotect(data, s_typeInfo, "Test", RandomNumberGenerator.GetBytes(32)));
    }

    [Fact]
    public void Unprotect_HmacRemoved_Throws()
    {
        string json = Encoding.UTF8.GetString(DeferredSessionEnvelope.Protect(new Session { Payload = [1] }, s_typeInfo, "Test", s_key));
        int start = json.IndexOf("\"hmac\":\"", StringComparison.Ordinal);
        int end = json.IndexOf('"', start + 8);
        byte[] withoutHmac = Encoding.UTF8.GetBytes(json.Remove(start + 8, end - start - 8));

        Should.Throw<CryptographicException>(() => DeferredSessionEnvelope.Unprotect(withoutHmac, s_typeInfo, "Test", s_key));
    }

    [Fact]
    public void Unprotect_SessionOfAnotherFormat_Throws()
    {
        // The format is part of what the HMAC covers: renaming it in the envelope does not make it pass either.
        byte[] data = DeferredSessionEnvelope.Protect(new Session { Payload = [1] }, s_typeInfo, "CAdES", s_key);
        byte[] renamed = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(data).Replace("\"format\":\"CAdES\"", "\"format\":\"XAdES\"", StringComparison.Ordinal));

        Should.Throw<ArgumentException>(() => DeferredSessionEnvelope.Unprotect(data, s_typeInfo, "XAdES", s_key));
        Should.Throw<CryptographicException>(() => DeferredSessionEnvelope.Unprotect(renamed, s_typeInfo, "XAdES", s_key));
    }

    [Fact]
    public void Unprotect_EnvelopeOfALaterVersion_ThrowsArgumentException()
    {
        string json = Encoding.UTF8.GetString(DeferredSessionEnvelope.Protect(new Session { Payload = [1] }, s_typeInfo, "Test", s_key));
        byte[] later = Encoding.UTF8.GetBytes(json.Replace("\"version\":1", "\"version\":2", StringComparison.Ordinal));

        Should.Throw<ArgumentException>(() => DeferredSessionEnvelope.Unprotect(later, s_typeInfo, "Test", s_key));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("[]")]
    [InlineData("{\"format\":\"Test\",\"version\":1,\"hmac\":\"AAAA\"}")]
    [InlineData("{\"format\":\"Test\",\"version\":1,\"hmac\":\"AAAA\",\"session\":\"text\"}")]
    public void Unprotect_DataThatIsNotASession_ThrowsArgumentException(string data) =>
        Should.Throw<ArgumentException>(() => DeferredSessionEnvelope.Unprotect(Encoding.UTF8.GetBytes(data), s_typeInfo, "Test", s_key));

    [Fact]
    public void ProtectAndUnprotect_KeyShorterThan32Bytes_Throw()
    {
        byte[] data = DeferredSessionEnvelope.Protect(new Session { Payload = [1] }, s_typeInfo, "Test", s_key);

        Should.Throw<ArgumentException>(() => DeferredSessionEnvelope.Protect(new Session { Payload = [1] }, s_typeInfo, "Test", new byte[31]));
        Should.Throw<ArgumentException>(() => DeferredSessionEnvelope.Unprotect(data, s_typeInfo, "Test", new byte[31]));
        Should.Throw<ArgumentNullException>(() => DeferredSessionEnvelope.Unprotect(data, s_typeInfo, "Test", null!));
    }

    [Fact]
    public void Unprotect_FieldTheReaderDoesNotKnow_IsIgnored()
    {
        // A later version of the library wrote one more field: the HMAC covers the stored bytes, so it still verifies.
        var laterTypeInfo = (JsonTypeInfo<LaterSession>)JsonSerializerOptions.Default.GetTypeInfo(typeof(LaterSession));
        byte[] data = DeferredSessionEnvelope.Protect(new LaterSession { Payload = [7], Level = 1, Added = "new" }, laterTypeInfo, "Test", s_key);

        Session session = DeferredSessionEnvelope.Unprotect(data, s_typeInfo, "Test", s_key);

        session.Payload.ShouldBe([7]);
        session.Level.ShouldBe(1);
    }

    [Fact]
    public void Unprotect_SessionWrittenBeforeAField_LeavesItAtItsDefault()
    {
        var laterTypeInfo = (JsonTypeInfo<LaterSession>)JsonSerializerOptions.Default.GetTypeInfo(typeof(LaterSession));
        byte[] data = DeferredSessionEnvelope.Protect(new Session { Payload = [7], Level = 1 }, s_typeInfo, "Test", s_key);

        LaterSession session = DeferredSessionEnvelope.Unprotect(data, laterTypeInfo, "Test", s_key);

        session.Payload.ShouldBe([7]);
        session.Added.ShouldBeNull();
    }

    private class Session
    {
        public required byte[] Payload { get; init; }

        public int Level { get; init; }
    }

    private sealed class LaterSession : Session
    {
        public string? Added { get; init; }
    }
}
