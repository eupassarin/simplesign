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

    /// <summary>The warning shown with the last PIN prompt, and whether it was shown as an error.</summary>
    public (string? Text, bool Severe) LastPinWarning { get; private set; }

    public Task<string?> AskSecretAsync(string title, string message, string confirmText, string? warning = null, bool severe = false)
    {
        LastPinWarning = (warning, severe);
        return Task.FromResult<string?>("1234");
    }

    public Task<ConsentDecision> AskConsentAsync(ConsentRequest request)
    {
        Asked.Add(request);
        return Task.FromResult(request.CertificateHolder is null ? Site : Signature);
    }
}

internal static class Fixtures
{
    public static AgentServices Services(FakeDialogs? dialogs = null, ManagedPolicy? policy = null) =>
        new(new SettingsStore(Directory.CreateTempSubdirectory("simplesign-agent-").FullName, policy ?? ManagedPolicy.None), dialogs ?? new FakeDialogs());

    /// <summary>The agent's services with those trust frameworks enabled.</summary>
    public static AgentServices ServicesWithTrust(FakeDialogs? dialogs, params string[] enabled)
    {
        var services = Services(dialogs);
        services.Settings.Current.EnabledTrustFrameworks = [.. enabled];
        return services;
    }

    public static X509Certificate2 RsaCertificate(string name = "CN=Fulano de Tal", int validDays = 365)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(name, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, true));
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-30), DateTimeOffset.UtcNow.AddDays(validDays));
        return X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx), null, CertificateService.KeyStorage);
    }

    public static X509Certificate2 EcdsaCertificate(string name = "CN=Beltrana de Souza")
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(name, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-30), DateTimeOffset.UtcNow.AddYears(2));
        return X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx), null, CertificateService.KeyStorage);
    }

    public static int FreePort()
    {
        using var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        return ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
    }
}
