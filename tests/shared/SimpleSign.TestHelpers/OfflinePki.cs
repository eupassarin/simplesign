using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;

namespace SimpleSign.TestHelpers;

/// <summary>
/// A PKI that signs with nothing reaching the network, for the interop and conformance tests: a <see cref="SyntheticPki"/> (root → intermediate →
/// RSA signer), an ECDSA P-256 signer and a TSA under the same intermediate, its CRLs and timestamps answered in memory,
/// and the certificates and keys written as PEM for external tools (<see cref="Directory"/>). Shared by the tests of a class.
/// </summary>
public sealed class OfflinePki : IDisposable
{
    private const string LeafCrlUrl = "http://198.51.100.1/leaf.crl";
    private const string IntermediateCrlUrl = "http://198.51.100.1/intermediate.crl";
    private static readonly Uri TsaUri = new("http://tsa.example.test/");

    private readonly HttpClient _http;

    public OfflinePki()
    {
        Pki = new SyntheticPki(crlDistributionPoint: LeafCrlUrl, intermediateCrlDistributionPoint: IntermediateCrlUrl);
        Tsa = Pki.IssueTimestampingCertificate();
        (Ecdsa, string ecdsaKey) = Pki.IssueEcdsaSigner();

        byte[] leafCrl = Pki.BuildLeafCrl();
        byte[] intermediateCrl = Pki.BuildIntermediateCrl();
        var tokens = new TimestampTokenOptions { TsaCertificate = Tsa, ExtraCertificates = [Pki.IntermediateCa] };
        _http = new HttpClient(new MockHttpHandler(async request =>
        {
            if (request.Method == HttpMethod.Post)
            {
                byte[] query = await request.Content!.ReadAsByteArrayAsync();
                var reply = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(TimestampTestResponseBuilder.CreateForRequest(query, tokens)) };
                reply.Content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-reply");
                return reply;
            }

            byte[]? crl = request.RequestUri?.ToString() switch
            {
                LeafCrlUrl => leafCrl,
                IntermediateCrlUrl => intermediateCrl,
                _ => null,
            };
            return crl is null
                ? new HttpResponseMessage(HttpStatusCode.NotFound)
                : new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(crl) };
        }));
        Http = new SingleClientProvider(_http);

        Directory = Path.Combine(Path.GetTempPath(), $"simplesign-pki-{Guid.NewGuid():N}");
        System.IO.Directory.CreateDirectory(Directory);
        RootPem = Write("root.pem", Pki.RootCa.ExportCertificatePem());
        ChainPem = Write("chain.pem", Pki.IntermediateCa.ExportCertificatePem());
        LeafPem = Write("leaf.pem", Pki.Leaf.ExportCertificatePem());
        LeafKeyPem = Write("leaf.key", Pki.LeafPrivateKeyPem());
        EcdsaPem = Write("ecdsa.pem", Ecdsa.ExportCertificatePem());
        EcdsaKeyPem = Write("ecdsa.key", ecdsaKey);
    }

    /// <summary>The root CA, intermediate CA and RSA signer.</summary>
    public SyntheticPki Pki { get; }

    /// <summary>An ECDSA P-256 signer under the intermediate, with its key.</summary>
    public X509Certificate2 Ecdsa { get; }

    /// <summary>The TSA that signs every timestamp, under the intermediate.</summary>
    public X509Certificate2 Tsa { get; }

    /// <summary>Answers the TSA and the CRLs; nothing reaches the network.</summary>
    public IHttpClientProvider Http { get; }

    /// <summary>A temporary folder holding the PEM files; deleted with this object.</summary>
    public string Directory { get; }

    /// <summary>The root certificate, the only trust anchor of every tool.</summary>
    public string RootPem { get; }

    /// <summary>The intermediate certificate.</summary>
    public string ChainPem { get; }

    /// <summary>The RSA signer's certificate.</summary>
    public string LeafPem { get; }

    /// <summary>The RSA signer's private key (PKCS#8).</summary>
    public string LeafKeyPem { get; }

    /// <summary>The ECDSA signer's certificate.</summary>
    public string EcdsaPem { get; }

    /// <summary>The ECDSA signer's private key (PKCS#8).</summary>
    public string EcdsaKeyPem { get; }

    /// <summary>This PKI's TSA, for an augmentation.</summary>
    public TimestampOptions Timestamp => new(TsaUri, Http);

    /// <summary>The certificates a signer embeds besides its own.</summary>
    public X509Certificate2[] Chain => Pki.IntermediatesAndRoot();

    /// <summary>The baseline level <paramref name="level"/> (<c>B</c>, <c>T</c>, <c>LT</c>, <c>LTA</c>), with this PKI's TSA and CRLs.</summary>
    public AdesBaselineProfile Level(string level) => level switch
    {
        "B" => AdesBaselineProfile.Basic(),
        "T" => AdesBaselineProfile.Timestamped(new TimestampOptions(TsaUri, Http)),
        "LT" => AdesBaselineProfile.LongTerm(new TimestampOptions(TsaUri, Http), new LongTermValidationOptions(Http)),
        "LTA" => AdesBaselineProfile.Archive(new TimestampOptions(TsaUri, Http), new LongTermValidationOptions(Http)),
        _ => throw new ArgumentOutOfRangeException(nameof(level), level, "B, T, LT or LTA"),
    };

    /// <summary>Writes <paramref name="content"/> to a new file in <see cref="Directory"/>.</summary>
    /// <returns>Its path.</returns>
    public string Write(string name, byte[] content)
    {
        string path = Path.Combine(Directory, $"{Guid.NewGuid():N}-{name}");
        File.WriteAllBytes(path, content);
        return path;
    }

    private string Write(string name, string text)
    {
        string path = Path.Combine(Directory, name);
        File.WriteAllText(path, text);
        return path;
    }

    public void Dispose()
    {
        _http.Dispose();
        Tsa.Dispose();
        Ecdsa.Dispose();
        Pki.Dispose();
        System.IO.Directory.Delete(Directory, recursive: true);
    }
}
