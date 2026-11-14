using System.Buffers.Text;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.Agent.Server;
using SimpleSign.Agent.Services;

namespace SimpleSign.Agent.Tests;

/// <summary>The server-signed sign requests (<c>signedRequestsRequired</c>) and every way one is refused.</summary>
[Trait("Category", "Unit")]
public sealed class SignedRequestTests : IDisposable
{
    private const string Origin = "https://portal.example.com";

    private readonly ECDsa _serverKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly X509Certificate2 _certificate = Fixtures.RsaCertificate();

    public void Dispose()
    {
        _serverKey.Dispose();
        _otherKey.Dispose();
        _certificate.Dispose();
    }

    [Fact]
    public void Verify_ModeOff_AndNoToken_ReturnsNull() =>
        Verifier(required: false).Verify(null, Origin, Request(), Payloads()).ShouldBeNull();

    [Fact]
    public void Verify_ModeOff_IgnoresATokenItWasSent() =>
        Verifier(required: false).Verify(Token(), Origin, Request(), Payloads()).ShouldBeNull();

    [Fact]
    public void Verify_ValidToken_IsAcceptedWithItsDocumentName()
    {
        var grant = Verifier().Verify(Token(), Origin, Request(), Payloads());

        grant.ShouldNotBeNull();
        grant.DocumentName.ShouldBe("contrato.pdf");
        grant.KeyId.ShouldBe(SignedRequestVerifier.KeyId(Pem(_serverKey)));
    }

    [Fact]
    public void Verify_ValidTokenWithoutKid_IsAccepted() =>
        Verifier().Verify(Token(kid: null), Origin, Request(), Payloads()).ShouldNotBeNull();

    [Fact]
    public void Verify_RsaKeyAndRs256_IsAccepted()
    {
        using var rsa = RSA.Create(2048);

        Verifier(keys: [Pem(rsa)]).Verify(Token(signer: rsa, algorithm: "RS256"), Origin, Request(), Payloads()).ShouldNotBeNull();
    }

    [Fact]
    public void Verify_RsaKeyAndPs256_IsAccepted()
    {
        using var rsa = RSA.Create(2048);

        Verifier(keys: [Pem(rsa)]).Verify(Token(signer: rsa, algorithm: "PS256"), Origin, Request(), Payloads()).ShouldNotBeNull();
    }

    [Fact]
    public void Verify_ModeOnButNoToken_IsRefused() =>
        Refusal(Verifier(), null).ShouldContain("signedRequest");

    [Fact]
    public void Verify_ModeOnWithNoConfiguredKey_IsRefused() =>
        Should.Throw<AgentRequestException>(() => Verifier(keys: []).Verify(Token(), Origin, Request(), Payloads()));

    [Theory]
    [InlineData("not-a-token")]
    [InlineData("a.b")]
    [InlineData("a.b.c.d")]
    [InlineData("!!.!!.!!")]
    public void Verify_NotAJws_IsRefused(string token) =>
        Should.Throw<AgentRequestException>(() => Verifier().Verify(token, Origin, Request(), Payloads()));

    [Fact]
    public void Verify_AlgorithmNone_IsRefused() =>
        Should.Throw<AgentRequestException>(() => Verifier().Verify(Unsigned("none"), Origin, Request(), Payloads()));

    [Fact]
    public void Verify_UnknownAlgorithm_IsRefused() =>
        Should.Throw<AgentRequestException>(() => Verifier().Verify(Unsigned("HS256"), Origin, Request(), Payloads()));

    [Fact]
    public void Verify_WrongTokenType_IsRefused() =>
        Should.Throw<AgentRequestException>(() => Verifier().Verify(Token(type: "jwt"), Origin, Request(), Payloads()));

    [Fact]
    public void Verify_SignedByAnotherKey_IsRefused() =>
        Should.Throw<AgentRequestException>(() => Verifier().Verify(Token(signer: _otherKey), Origin, Request(), Payloads()));

    [Fact]
    public void Verify_TamperedPayload_IsRefused()
    {
        string[] parts = Token().Split('.');
        string tampered = parts[0] + "." + Encode(Claims(documentName: "outro.pdf")) + "." + parts[2];

        Should.Throw<AgentRequestException>(() => Verifier().Verify(tampered, Origin, Request(), Payloads()));
    }

    [Fact]
    public void Verify_Expired_IsRefused() =>
        Should.Throw<AgentRequestException>(() => Verifier().Verify(
            Token(issuedAt: Now - 600, expires: Now - 300), Origin, Request(), Payloads()));

    [Fact]
    public void Verify_LifetimeLongerThanAllowed_IsRefused() =>
        Should.Throw<AgentRequestException>(() => Verifier().Verify(
            Token(issuedAt: Now, expires: Now + SignedRequestVerifier.MaxLifetimeSeconds + 600), Origin, Request(), Payloads()));

    [Fact]
    public void Verify_IssuedInTheFuture_IsRefused() =>
        Should.Throw<AgentRequestException>(() => Verifier().Verify(
            Token(issuedAt: Now + 600, expires: Now + 700), Origin, Request(), Payloads()));

    [Fact]
    public void Verify_NoExpiry_IsRefused() =>
        Should.Throw<AgentRequestException>(() => Verifier().Verify(
            Token(issuedAt: Now, expires: 0), Origin, Request(), Payloads()));

    [Fact]
    public void Verify_SameTokenTwice_IsRefusedTheSecondTime()
    {
        var verifier = Verifier();
        string token = Token();

        verifier.Verify(token, Origin, Request(), Payloads()).ShouldNotBeNull();
        Should.Throw<AgentRequestException>(() => verifier.Verify(token, Origin, Request(), Payloads()));
    }

    [Fact]
    public void Verify_NoNonce_IsRefused() =>
        Should.Throw<AgentRequestException>(() => Verifier().Verify(Token(nonce: ""), Origin, Request(), Payloads()));

    [Fact]
    public void Verify_AnotherOrigin_IsRefused() =>
        Should.Throw<AgentRequestException>(() => Verifier().Verify(Token(), "https://evil.example.net", Request(), Payloads()));

    [Fact]
    public void Verify_AnotherAudience_IsRefused() =>
        Should.Throw<AgentRequestException>(() => Verifier().Verify(Token(audience: "someone-else"), Origin, Request(), Payloads()));

    [Fact]
    public void Verify_AnotherCertificate_IsRefused() =>
        Should.Throw<AgentRequestException>(() => Verifier().Verify(
            Token(thumbprint: "0000000000000000000000000000000000000000"), Origin, Request(), Payloads()));

    [Fact]
    public void Verify_AnotherHashAlgorithm_IsRefused() =>
        Should.Throw<AgentRequestException>(() => Verifier().Verify(Token(hashAlgorithm: "SHA512"), Origin, Request(), Payloads()));

    [Fact]
    public void Verify_TheRequestedHashAlgorithmSpelledWithADash_IsAccepted() =>
        Verifier().Verify(Token(hashAlgorithm: "SHA-256"), Origin, Request(), Payloads()).ShouldNotBeNull();

    [Fact]
    public void Verify_OtherBytesThanTheTokenCovers_IsRefused()
    {
        var payloads = Payloads(Attributes("another document"));

        Should.Throw<AgentRequestException>(() => Verifier().Verify(Token(), Origin, Request(), payloads));
    }

    [Fact]
    public void Verify_MoreItemsThanTheTokenCovers_IsRefused()
    {
        var payloads = Payloads(Attributes("one"), Attributes("two"));
        var request = Request();
        request.SignRequests!.Add(new AgentSignRequestItem { Id = "2" });

        Should.Throw<AgentRequestException>(() => Verifier().Verify(Token(), Origin, request, payloads));
    }

    [Fact]
    public void Verify_ItemsInAnotherOrder_IsRefused()
    {
        byte[] one = Attributes("one");
        byte[] two = Attributes("two");
        string token = Token(items: [("1", one), ("2", two)]);
        var request = Request();
        request.SignRequests!.Add(new AgentSignRequestItem { Id = "2" });

        Should.Throw<AgentRequestException>(() => Verifier().Verify(token, Origin, request, Payloads(two, one)));
    }

    [Fact]
    public void Verify_EveryItemCovered_IsAccepted()
    {
        byte[] one = Attributes("one");
        byte[] two = Attributes("two");
        var request = Request();
        request.SignRequests!.Add(new AgentSignRequestItem { Id = "2" });

        Verifier().Verify(Token(items: [("1", one), ("2", two)]), Origin, request, Payloads(one, two)).ShouldNotBeNull();
    }

    [Fact]
    public void KeyId_SameKeyTwice_IsStableAndDiffersBetweenKeys()
    {
        SignedRequestVerifier.KeyId(Pem(_serverKey)).ShouldBe(SignedRequestVerifier.KeyId(Pem(_serverKey)));
        SignedRequestVerifier.KeyId(Pem(_serverKey)).ShouldNotBe(SignedRequestVerifier.KeyId(Pem(_otherKey)));
    }

    [Fact]
    public void KeyId_NotAPublicKey_ThrowsArgumentException() =>
        Should.Throw<ArgumentException>(() => SignedRequestVerifier.KeyId("not a pem"));

    private static long Now => DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    private static string Refusal(SignedRequestVerifier verifier, string? token) =>
        Should.Throw<AgentRequestException>(() => verifier.Verify(token, Origin, Request(), Payloads())).Message;

    private SignedRequestVerifier Verifier(bool required = true, IReadOnlyList<string>? keys = null)
    {
        var store = new SettingsStore(Directory.CreateTempSubdirectory("simplesign-agent-").FullName, ManagedPolicy.None);
        store.Current.SignedRequestsRequired = required;
        store.Current.SignedRequestKeys = [.. keys ?? [Pem(_serverKey)]];
        return new SignedRequestVerifier(store);
    }

    private static string Pem(ECDsa key) => key.ExportSubjectPublicKeyInfoPem();

    private static string Pem(RSA key) => key.ExportSubjectPublicKeyInfoPem();

    /// <summary>DER CMS signed attributes the agent accepts: contentType and messageDigest over <paramref name="content"/>.</summary>
    private static byte[] Attributes(string content = "contract")
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSetOf())
        {
            Attribute(writer, "1.2.840.113549.1.9.3", w => w.WriteObjectIdentifier("1.2.840.113549.1.7.1"));
            Attribute(writer, "1.2.840.113549.1.9.4", w => w.WriteOctetString(SHA256.HashData(Encoding.UTF8.GetBytes(content))));
        }

        return writer.Encode();
    }

    private static void Attribute(AsnWriter writer, string oid, Action<AsnWriter> value)
    {
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(oid);
            using (writer.PushSetOf())
            {
                value(writer);
            }
        }
    }

    private static List<AgentSigner.SignRequestBytes> Payloads(params byte[][] items)
    {
        byte[][] bytes = items.Length > 0 ? items : [Attributes()];
        return [.. bytes.Select((data, i) => new AgentSigner.SignRequestBytes(
            (i + 1).ToString(System.Globalization.CultureInfo.InvariantCulture), data))];
    }

    private static AgentSignRequest Request() => new()
    {
        Thumbprint = "ABCDEF",
        HashAlgorithm = "SHA256",
        DocumentName = "from-the-page.pdf",
        SignRequests = [new AgentSignRequestItem { Id = "1" }],
    };

    private string Token(
        string? kid = "",
        string? type = SignedRequestVerifier.TokenType,
        string audience = SignedRequestVerifier.Audience,
        string origin = Origin,
        string? thumbprint = "ABCDEF",
        string? hashAlgorithm = "SHA256",
        string documentName = "contrato.pdf",
        string? nonce = null,
        long? issuedAt = null,
        long? expires = null,
        IReadOnlyList<(string Id, byte[] Data)>? items = null,
        object? signer = null,
        string algorithm = "ES256")
    {
        object key = signer ?? _serverKey;
        string id = kid is "" ? KeyIdOf(key) : kid ?? "";
        string header = "{" + $"\"alg\":\"{algorithm}\",\"typ\":\"{type}\"" + (id.Length > 0 ? $",\"kid\":\"{id}\"" : "") + "}";
        string claims = Claims(audience, origin, thumbprint, hashAlgorithm, documentName,
            nonce ?? Guid.NewGuid().ToString("N"), issuedAt ?? Now, expires ?? Now + 120,
            items ?? [("1", Attributes())]);
        string signingInput = Encode(header) + "." + Encode(claims);
        byte[] signature = Sign(key, algorithm, Encoding.ASCII.GetBytes(signingInput));
        return signingInput + "." + Base64Url.EncodeToString(signature);
    }

    private static string KeyIdOf(object key) =>
        SignedRequestVerifier.KeyId(key is ECDsa ec ? Pem(ec) : Pem((RSA)key));

    private static byte[] Sign(object key, string algorithm, byte[] data)
    {
        var hash = algorithm.EndsWith("384", StringComparison.Ordinal) ? HashAlgorithmName.SHA384
            : algorithm.EndsWith("512", StringComparison.Ordinal) ? HashAlgorithmName.SHA512
            : HashAlgorithmName.SHA256;
        return key switch
        {
            ECDsa ec => ec.SignData(data, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
            RSA rsa => rsa.SignData(data, hash, algorithm.StartsWith("PS", StringComparison.Ordinal)
                ? RSASignaturePadding.Pss
                : RSASignaturePadding.Pkcs1),
            _ => throw new NotSupportedException(),
        };
    }

    private static string Unsigned(string algorithm)
    {
        string header = "{" + $"\"alg\":\"{algorithm}\",\"typ\":\"{SignedRequestVerifier.TokenType}\"" + "}";
        return Encode(header) + "." + Encode(Claims()) + ".";
    }

    private static string Claims(
        string audience = SignedRequestVerifier.Audience,
        string origin = Origin,
        string? thumbprint = "ABCDEF",
        string? hashAlgorithm = "SHA256",
        string documentName = "contrato.pdf",
        string nonce = "n1",
        long? issuedAt = null,
        long? expires = null,
        IReadOnlyList<(string Id, byte[] Data)>? items = null)
    {
        var list = items ?? [("1", Attributes())];
        string entries = string.Join(",", list.Select(i =>
            $"{{\"id\":\"{i.Id}\",\"digest\":\"{Base64Url.EncodeToString(SHA256.HashData(i.Data))}\"}}"));
        return "{"
            + $"\"aud\":\"{audience}\",\"origin\":\"{origin}\",\"thumbprint\":\"{thumbprint}\","
            + $"\"hashAlgorithm\":\"{hashAlgorithm}\",\"documentName\":\"{documentName}\","
            + $"\"items\":[{entries}],\"iat\":{issuedAt ?? Now},\"exp\":{expires ?? Now + 120},\"jti\":\"{nonce}\""
            + "}";
    }

    private static string Encode(string json) => Base64Url.EncodeToString(Encoding.UTF8.GetBytes(json));
}
