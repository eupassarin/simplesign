using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Http;
using SimpleSign.TestHelpers;

namespace SimpleSign.Peru.Iofe.Accredited.Tests;

/// <summary>
/// A test PKI (root, intermediate, signer) whose CRLs and time-stamp authority answer on addresses no network reaches,
/// with the failures a test switches on: the signer revoked, the CRLs unavailable.
/// </summary>
internal sealed class IofeTestPki : IDisposable
{
    public const string LeafCrlUrl = "http://198.51.100.30/leaf.crl";
    public const string IntermediateCrlUrl = "http://198.51.100.30/intermediate.crl";
    public const string TsaUrl = "http://198.51.100.30/tsa";

    private readonly HttpClient _client;
    private readonly X509Certificate2 _impostorTsa;
    private readonly byte[] _tsaRevokedCrl;
    private readonly byte[] _goodLeafCrl;
    private readonly byte[] _revokedLeafCrl;
    private readonly byte[] _intermediateCrl;

    public IofeTestPki()
    {
        Pki = new SyntheticPki(crlDistributionPoint: LeafCrlUrl, intermediateCrlDistributionPoint: IntermediateCrlUrl);
        _goodLeafCrl = Pki.BuildLeafCrl();
        _revokedLeafCrl = Pki.BuildRevokedLeafCrl();
        _intermediateCrl = Pki.BuildIntermediateCrl();
        Tsa = Pki.IssueTimestampingCertificate();
        _impostorTsa = Pki.IssueTimestampingCertificate("CN=Otra TSA, O=SimpleSign Tests");
        _tsaRevokedCrl = Pki.BuildCrlRevoking(Tsa);
        _client = new HttpClient(new MockHttpHandler(AnswerAsync));
        Provider = new PolicyHttpClientProvider(_client, OutboundHttpPolicy.Default);
    }

    public SyntheticPki Pki { get; }

    public IHttpClientProvider Provider { get; }

    /// <summary>Whether the CRL of the signer's CA lists the signer (<see cref="SyntheticPki.Leaf"/>) as revoked.</summary>
    public bool LeafRevoked { get; set; }

    /// <summary>Whether the CRL distribution points fail.</summary>
    public bool CrlsDown { get; set; }

    /// <summary>The certificate of the time-stamp authority at <see cref="TsaUrl"/>.</summary>
    public X509Certificate2 Tsa { get; }

    /// <summary>Whether the CRL lists the time-stamp authority's certificate as revoked.</summary>
    public bool TsaRevoked { get; set; }

    /// <summary>Whether the tokens come with a broken signature.</summary>
    public bool TsaTampered { get; set; }

    /// <summary>Whether another authority of the same PKI answers at <see cref="TsaUrl"/>.</summary>
    public bool TsaImpostor { get; set; }

    /// <summary>What answers the requests to <see cref="FakeRemoteSigningService.Host"/>; null when no remote signing service is up.</summary>
    public Func<HttpRequestMessage, Task<HttpResponseMessage>>? RemoteService { get; set; }

    public void Reset()
    {
        LeafRevoked = false;
        CrlsDown = false;
        TsaRevoked = false;
        TsaTampered = false;
        TsaImpostor = false;
    }

    /// <summary>A signer under the intermediate CA with the given key usage and the CRL distribution point of the leaf.</summary>
    public X509Certificate2 IssueSigner(string subject, RSA key, X509KeyUsageFlags keyUsage)
    {
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(keyUsage, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(Pki.IntermediateCa, true, false));
        request.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([LeafCrlUrl]));
        byte[] serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F;
        var notBefore = Pki.IntermediateCa.NotBefore.ToUniversalTime().AddMinutes(1);
        return request.Create(Pki.IntermediateCa, notBefore, notBefore.AddYears(1), serial);
    }

    public void Dispose()
    {
        _client.Dispose();
        Tsa.Dispose();
        _impostorTsa.Dispose();
        Pki.Dispose();
    }

    private async Task<HttpResponseMessage> AnswerAsync(HttpRequestMessage request)
    {
        if (RemoteService is not null && request.RequestUri?.Host == FakeRemoteSigningService.Host)
        {
            return await RemoteService(request).ConfigureAwait(false);
        }

        if (request.Method == HttpMethod.Post)
        {
            byte[] query = await request.Content!.ReadAsByteArrayAsync().ConfigureAwait(false);
            byte[] token = TimestampTestResponseBuilder.CreateForRequest(query, new TimestampTokenOptions
            {
                TsaCertificate = TsaImpostor ? _impostorTsa : Tsa,
                ExtraCertificates = [Pki.IntermediateCa],
                GenTime = DateTimeOffset.UtcNow,
                TamperSignature = TsaTampered,
            });
            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(token) };
            response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-reply");
            return response;
        }

        if (CrlsDown)
        {
            return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        }

        byte[]? crl = request.RequestUri?.ToString() switch
        {
            LeafCrlUrl => LeafRevoked ? _revokedLeafCrl : TsaRevoked ? _tsaRevokedCrl : _goodLeafCrl,
            IntermediateCrlUrl => _intermediateCrl,
            _ => null,
        };
        return crl is null
            ? new HttpResponseMessage(HttpStatusCode.NotFound)
            : new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(crl) };
    }
}

/// <summary>Keeps the verification records it receives, in order.</summary>
internal sealed class RecordingVerificationAuditSink : IVerificationAuditSink
{
    public List<IofeVerificationAuditEvent> Events { get; } = [];

    public ValueTask RecordAsync(IofeVerificationAuditEvent auditEvent, CancellationToken cancellationToken)
    {
        Events.Add(auditEvent);
        return ValueTask.CompletedTask;
    }
}

/// <summary>Keeps the notices it is given, or fails when told to.</summary>
internal sealed class RecordingNotifier : IIofeSenderNotifier
{
    public List<IofeRejectionNotice> Notices { get; } = [];

    public bool Fails { get; set; }

    public ValueTask NotifyAsync(IofeRejectionNotice notice, CancellationToken cancellationToken)
    {
        if (Fails)
        {
            throw new IOException("mail server unreachable");
        }

        Notices.Add(notice);
        return ValueTask.CompletedTask;
    }
}
