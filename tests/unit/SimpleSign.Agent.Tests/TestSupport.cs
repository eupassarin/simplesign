using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Agent.Services;

namespace SimpleSign.Agent.Tests;

/// <summary>Dialogs answered by the test.</summary>
internal sealed class FakeDialogs : IDialogService
{
    public ConsentDecision Site { get; set; } = ConsentDecision.AllowOnce;

    public ConsentDecision Signature { get; set; } = ConsentDecision.AllowOnce;

    public List<ConsentRequest> Asked { get; } = [];

    public Task<string?> AskSecretAsync(string title, string message, string confirmText) => Task.FromResult<string?>("1234");

    public Task<ConsentDecision> AskConsentAsync(ConsentRequest request)
    {
        Asked.Add(request);
        return Task.FromResult(request.CertificateHolder is null ? Site : Signature);
    }
}

internal static class Fixtures
{
    public static AgentServices Services(FakeDialogs? dialogs = null) =>
        new(new SettingsStore(Directory.CreateTempSubdirectory("simplesign-agent-").FullName), dialogs ?? new FakeDialogs());

    public static X509Certificate2 RsaCertificate(string name = "CN=Fulano de Tal")
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(name, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx), null, CertificateService.KeyStorage);
    }
}
