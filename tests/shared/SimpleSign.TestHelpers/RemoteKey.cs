using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization.Metadata;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;

namespace SimpleSign.TestHelpers;

/// <summary>
/// Plays the machine that holds the private key in a two-phase signature: the server sees only the
/// public certificate, and this signs the bytes it is sent.
/// </summary>
public static class RemoteKey
{
    /// <summary>The certificate without its private key, as the server of a two-phase signature has it.</summary>
    /// <param name="certificate">A certificate, with or without a private key.</param>
    public static X509Certificate2 PublicOnly(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return CertificateLoader.LoadCertificate(certificate.RawData);
    }

    /// <summary>Signs the data of <paramref name="request"/> with the private key of <paramref name="certificate"/>.</summary>
    /// <param name="certificate">The certificate that owns the private key.</param>
    /// <param name="request">The signing request of the prepared signature.</param>
    /// <returns>The raw signature: RSA PKCS#1 v1.5 or PSS, or an ECDSA DER SEQUENCE.</returns>
    public static byte[] Sign(X509Certificate2 certificate, ExternalSigningRequest request)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(request);
        using RSA? rsa = certificate.GetRSAPrivateKey();
        if (rsa is not null)
        {
            return rsa.SignData(
                request.DataToSign.Span, request.HashAlgorithm,
                request.SignatureAlgorithmOid == Oids.RsaPss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);
        }

        using ECDsa ecdsa = certificate.GetECDsaPrivateKey()
            ?? throw new InvalidOperationException("The certificate has no RSA or ECDSA private key.");
        return ecdsa.SignData(request.DataToSign.Span, request.HashAlgorithm, DSASignatureFormat.Rfc3279DerSequence);
    }

    /// <summary>
    /// Rewrites the session inside a deferred-session envelope and authenticates it again with
    /// <paramref name="key"/>: what a session written by another version of the library looks like.
    /// </summary>
    /// <param name="sessionData">A session returned by phase one.</param>
    /// <param name="key">The session integrity key.</param>
    /// <param name="change">The change to make to the session object.</param>
    public static byte[] RewriteSession(byte[] sessionData, byte[] key, Action<JsonObject> change)
    {
        ArgumentNullException.ThrowIfNull(change);
        JsonObject envelope = JsonNode.Parse(sessionData)!.AsObject();
        JsonObject session = envelope["session"]!.AsObject();
        change(session);
        using JsonDocument document = JsonDocument.Parse(session.ToJsonString());
        var typeInfo = (JsonTypeInfo<JsonElement>)JsonSerializerOptions.Default.GetTypeInfo(typeof(JsonElement));
        return DeferredSessionEnvelope.Protect(document.RootElement, typeInfo, envelope["format"]!.GetValue<string>(), key);
    }
}
