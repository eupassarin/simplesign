using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestHelpers;

namespace SimpleSign.Adobe.Aatl.Tests;

/// <summary>An identity of a test list: the certificate and what the list says of it.</summary>
/// <param name="Certificate">The certificate.</param>
/// <param name="Action">ImportAction.</param>
/// <param name="Root">Trust/Root.</param>
/// <param name="Policies">The certificate policies it is restricted to; none for no restriction.</param>
internal sealed record TestIdentity(X509Certificate2 Certificate, int Action = 1, bool Root = true, params string[] Policies);

/// <summary>
/// Builds lists laid out as Adobe's: a PDF that embeds <c>SecuritySettings.xml</c>, signed by a publisher under its own
/// root (the test's stand-in for the Adobe root).
/// </summary>
internal sealed class AatlListBuilder : IDisposable
{
    private readonly SyntheticPki _publisher = new();

    /// <summary>The root the lists' signatures chain to.</summary>
    public X509Certificate2 Root => _publisher.RootCa;

    /// <summary>Options that read the lists of this builder, without asking about the publisher's revocation.</summary>
    public AatlOptions Options => new() { ListSigners = [Root], CheckRevocation = false };

    /// <summary>A signed list.</summary>
    /// <param name="identities">The identities.</param>
    /// <param name="signedAt">The signing time; now by default.</param>
    public Task<byte[]> ListAsync(IEnumerable<TestIdentity> identities, DateTimeOffset? signedAt = null) =>
        SignAsync(TestPdfFactory.CreatePdfWithAttachments((AatlList.SettingsFileName, Encoding.UTF8.GetBytes(Xml(identities)))), signedAt);

    /// <summary>Signs a PDF as the publisher signs its lists.</summary>
    public Task<byte[]> SignAsync(byte[] pdf, DateTimeOffset? signedAt = null) =>
        PadesSigner.Document(pdf)
            .WithCertificate(_publisher.Leaf, _publisher.IntermediatesAndRoot())
            .WithSubFilter(PdfSignatureSubFilter.AdbePkcs7Detached)
            .WithSigningTime(signedAt ?? DateTimeOffset.UtcNow)
            .SignAsync();

    /// <summary>The XML of the identities, as <c>SecuritySettings.xml</c> has them.</summary>
    public static string Xml(IEnumerable<TestIdentity> identities)
    {
        var xml = new StringBuilder("<?xml version=\"1.0\"?>\n<SecuritySettings>\n\t<TrustedIdentities>\n");
        foreach (var identity in identities)
        {
            string policies = identity.Policies.Length == 0
                ? ""
                : $"<Description>Hardware</Description><CertificatePolicies>{string.Concat(identity.Policies.Select(p => $"<OID>{p}</OID>"))}</CertificatePolicies>";
            xml.Append(System.Globalization.CultureInfo.InvariantCulture, $"""
                		<Identity>
                			<ImportAction>{identity.Action}</ImportAction>
                			<Certificate>{Convert.ToBase64String(identity.Certificate.RawData)}</Certificate>
                			<Trust><Root>{(identity.Root ? 1 : 0)}</Root><CertifiedDocuments>1</CertifiedDocuments><DynamicContent>0</DynamicContent></Trust>
                			<PolicyRestrictions>{policies}<NonExplicitProcessing>0</NonExplicitProcessing></PolicyRestrictions>
                			<Identification><Source>AATL</Source></Identification>
                		</Identity>

                """);
        }

        return xml.Append("\t</TrustedIdentities>\n</SecuritySettings>\n").ToString();
    }

    public void Dispose() => _publisher.Dispose();
}

/// <summary>A certification authority and the signer certificates it issues, with the certificate policies asked for.</summary>
internal sealed class PolicyCa : IDisposable
{
    private readonly RSA _key = RSA.Create(2048);
    private readonly List<IDisposable> _issued = [];

    public PolicyCa(string name)
    {
        var request = new CertificateRequest($"CN={name}, O=SimpleSign Tests", _key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: false, 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));
        Root = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));
    }

    /// <summary>The self-signed certificate of the authority.</summary>
    public X509Certificate2 Root { get; }

    /// <summary>A signer certificate, with its private key, that asserts <paramref name="policies"/> (none: no certificatePolicies extension).</summary>
    public X509Certificate2 Issue(string name, params string[] policies)
    {
        var key = RSA.Create(2048);
        _issued.Add(key);
        var request = new CertificateRequest($"CN={name}, O=SimpleSign Tests", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: false, hasPathLengthConstraint: false, 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, critical: true));
        if (policies.Length > 0)
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);
            using (writer.PushSequence())
            {
                foreach (string policy in policies)
                {
                    using (writer.PushSequence())
                    {
                        writer.WriteObjectIdentifier(policy);
                    }
                }
            }

            request.CertificateExtensions.Add(new X509Extension("2.5.29.32", writer.Encode(), critical: false));
        }

        byte[] serial = RandomNumberGenerator.GetBytes(8);
        serial[0] &= 0x7F;
        using var issued = request.Create(Root, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), serial);
        var signer = issued.CopyWithPrivateKey(key);
        _issued.Add(signer);
        return signer;
    }

    public void Dispose()
    {
        foreach (var disposable in _issued)
        {
            disposable.Dispose();
        }

        Root.Dispose();
        _key.Dispose();
    }
}
