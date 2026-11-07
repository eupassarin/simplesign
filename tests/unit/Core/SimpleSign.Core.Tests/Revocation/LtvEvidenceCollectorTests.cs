using System.Net;
using System.Net.Sockets;
using Shouldly;
using SimpleSign.Core.Http;
using SimpleSign.Core.Revocation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Revocation;

/// <summary>
/// LTV collection for a certificate whose only CRL distribution point is an LDAP URL: the CRL is
/// read over LDAP when the outbound policy allows it, and never otherwise.
/// </summary>
[Trait("Category", "Unit")]
public sealed class LtvEvidenceCollectorTests
{
    // The intermediate's CRL points at a host the policy refuses, so only the leaf's LDAP CRL is fetched.
    private const string RefusedHttpCrl = "http://localhost/intermediate.crl";

    [Fact]
    public async Task CollectAsync_LdapOnlyLeaf_LdapAllowed_EmbedsTheLdapCrl()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var pki = new SyntheticPki(
            crlDistributionPoint: $"ldap://127.0.0.1:{port}/cn=CA,c=PE",
            intermediateCrlDistributionPoint: RefusedHttpCrl);
        byte[] crl = pki.BuildLeafCrl();
        var server = LdapCrlClientTests.ServeOnceAsync(listener, "certificateRevocationList;binary", crl, resultCode: 0);
        var policy = new OutboundHttpPolicy { AllowLdap = true, LoopbackOrigins = [new Uri($"ldap://127.0.0.1:{port}")] };
        using var http = new HttpClient();

        var evidence = await LtvEvidenceCollector.CollectAsync(
            http, pki.Leaf, pki.IntermediatesAndRoot(), null, outboundPolicy: policy);

        (await server).ShouldBe("cn=CA,c=PE");
        evidence.Crls.ShouldHaveSingleItem().ShouldBe(crl);
        var leaf = evidence.CertificateEvidence!.Single(e => e.Thumbprint == pki.Leaf.Thumbprint);
        leaf.IsComplete.ShouldBeTrue();
        leaf.RevocationEvidenceKind.ShouldBe(LtvEvidenceKind.Crl);
    }

    [Fact]
    public async Task CollectAsync_LdapOnlyLeaf_LdapNotAllowed_CollectsNoCrl()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var pki = new SyntheticPki(
            crlDistributionPoint: $"ldap://127.0.0.1:{port}/cn=CA,c=PE",
            intermediateCrlDistributionPoint: RefusedHttpCrl);
        var policy = new OutboundHttpPolicy { LoopbackOrigins = [new Uri($"ldap://127.0.0.1:{port}")] };
        using var http = new HttpClient();

        var evidence = await LtvEvidenceCollector.CollectAsync(
            http, pki.Leaf, pki.IntermediatesAndRoot(), null, outboundPolicy: policy);

        listener.Pending().ShouldBeFalse();
        evidence.Crls.ShouldBeEmpty();
        var leaf = evidence.CertificateEvidence!.Single(e => e.Thumbprint == pki.Leaf.Thumbprint);
        leaf.IsComplete.ShouldBeFalse();
        leaf.RevocationEvidenceKind.ShouldBe(LtvEvidenceKind.None);
    }

    [Fact]
    public async Task CollectAsync_LdapServerDown_ReportsTheLdapFailure()
    {
        int port;
        using (var probe = new TcpListener(IPAddress.Loopback, 0))
        {
            probe.Start();
            port = ((IPEndPoint)probe.LocalEndpoint).Port;
        }

        using var pki = new SyntheticPki(
            crlDistributionPoint: $"ldap://127.0.0.1:{port}/cn=CA,c=PE",
            intermediateCrlDistributionPoint: RefusedHttpCrl);
        var policy = new OutboundHttpPolicy { AllowLdap = true, LoopbackOrigins = [new Uri($"ldap://127.0.0.1:{port}")] };
        using var http = new HttpClient();

        var evidence = await LtvEvidenceCollector.CollectAsync(
            http, pki.Leaf, pki.IntermediatesAndRoot(), null, outboundPolicy: policy);

        evidence.Crls.ShouldBeEmpty();
        var leaf = evidence.CertificateEvidence!.Single(e => e.Thumbprint == pki.Leaf.Thumbprint);
        leaf.AbsenceReason.ShouldNotBeNull().ShouldContain("LDAP");
    }
}
