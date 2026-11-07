using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.CAdES;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;
using SimpleSign.Sandbox.Services;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES;

namespace SimpleSign.Sandbox.Tests;

/// <summary>
/// B-LT signing, in each format, with a certificate whose only CRL distribution point is an
/// <c>ldap://</c> URL: the library reads that CRL over LDAP for the LTV material when the outbound
/// policy allows LDAP, and refuses the level when it does not.
/// </summary>
[Collection(SandboxCollection.Name)]
[Trait("Category", "Unit")]
public sealed class SandboxLtvTests(SandboxFixture fixture)
{
    private const string LdapOnly = "good-crl-ldap";

    [Theory]
    [InlineData("PAdES")]
    [InlineData("CAdES")]
    [InlineData("XAdES")]
    public async Task LongTerm_LdapOnlyCertificate_LdapAllowed_EmbedsTheLdapCrl(string format)
    {
        var (level, hasLtv) = await SignAsync(format, fixture.Policy, SigningPolicy.Strict);

        level.ShouldBe(AdesBaselineLevel.LongTerm);
        hasLtv.ShouldBeTrue();
        var log = await fixture.Http.GetFromJsonAsync<SandboxRequest[]>("api/log", SandboxFixture.Json);
        log!.ShouldContain(r => r.Service == "CRL (LDAP)" && r.Status == 0);
    }

    [Theory]
    [InlineData("PAdES")]
    [InlineData("CAdES")]
    [InlineData("XAdES")]
    public async Task LongTerm_LdapOnlyCertificate_LdapNotAllowed_LevelNotAchievable(string format)
    {
        var policy = fixture.Policy with { AllowLdap = false };

        var ex = await Should.ThrowAsync<SigningException>(() => SignAsync(format, policy, SigningPolicy.Default));

        ex.Reason.ShouldBe(SigningErrorReason.LevelNotAchievable);
    }

    private async Task<(AdesBaselineLevel Level, bool HasLtv)> SignAsync(string format, OutboundHttpPolicy outbound, SigningPolicy signing)
    {
        byte[] pfx = await fixture.Http.GetByteArrayAsync($"api/certificates/{LdapOnly}/pfx");
        var collection = X509CertificateLoader.LoadPkcs12Collection(pfx, fixture.Info.PfxPassword);
        try
        {
            var signer = collection.Single(c => c.HasPrivateKey);
            X509Certificate2[] chain = [.. collection.Where(c => !c.HasPrivateKey)];
            var provider = new SingleClientProvider(fixture.Client) { OutboundPolicy = outbound };
            var profile = AdesBaselineProfile.LongTerm(
                new TimestampOptions(new Uri(fixture.Info.Tsa.Url), provider),
                new LongTermValidationOptions(provider));

            switch (format)
            {
                case "PAdES":
                    var pades = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage())
                        .WithCertificate(signer, chain).WithLevel(profile).WithHttpClientProvider(provider).WithSigningPolicy(signing)
                        .SignWithDetailsAsync();
                    return (pades.AchievedLevel, pades.HasLongTermValidationMaterial);
                case "CAdES":
                    var cades = await CadesSigner.Document(Encoding.UTF8.GetBytes("sign me"))
                        .WithCertificate(signer, chain).WithLevel(profile).WithHttpClientProvider(provider).WithSigningPolicy(signing)
                        .SignWithDetailsAsync();
                    return (cades.AchievedLevel, cades.HasLongTermValidationMaterial);
                default:
                    var xades = await XadesSigner.Document(Encoding.UTF8.GetBytes("<doc>sign me</doc>"))
                        .WithCertificate(signer, chain).WithLevel(profile).WithHttpClientProvider(provider).WithSigningPolicy(signing)
                        .SignWithDetailsAsync();
                    return (xades.AchievedLevel, xades.HasLongTermValidationMaterial);
            }
        }
        finally
        {
            foreach (var certificate in collection)
            {
                certificate.Dispose();
            }
        }
    }
}
