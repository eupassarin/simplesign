using System.Net;
using System.Net.Sockets;
using Shouldly;
using SimpleSign.Core.Http;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Tests.Revocation;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Validation;

/// <summary>
/// The online CRL step of validation for a certificate whose only CRL distribution point is an
/// LDAP URL: read over LDAP when the CRL client's policy allows it, never otherwise.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RevocationCheckerTests
{
    [Fact]
    public async Task CheckRevocationAsync_LdapOnlyCertificate_LdapAllowed_ReadsTheCrlOnline()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var pki = new SyntheticPki(crlDistributionPoint: $"ldap://127.0.0.1:{port}/cn=CA,c=PE");
        var server = LdapCrlClientTests.ServeOnceAsync(listener, "certificateRevocationList;binary", pki.BuildLeafCrl(), resultCode: 0);
        var policy = new OutboundHttpPolicy { AllowLdap = true, LoopbackOrigins = [new Uri($"ldap://127.0.0.1:{port}")] };
        using var http = new HttpClient();
        var checker = new RevocationChecker(new OcspClient(http), new CrlClient(http) { OutboundPolicy = policy });

        var (notRevoked, source) = await checker.CheckRevocationAsync(pki.Leaf, pki.Chain(), [], CancellationToken.None);

        (await server).ShouldBe("cn=CA,c=PE");
        notRevoked.ShouldBeTrue();
        source.ShouldBe(RevocationSource.OnlineCrl);
    }

    [Fact]
    public async Task CheckRevocationAsync_LdapOnlyCertificate_LdapNotAllowed_IsIndeterminate()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var pki = new SyntheticPki(crlDistributionPoint: $"ldap://127.0.0.1:{port}/cn=CA,c=PE");
        var policy = new OutboundHttpPolicy { LoopbackOrigins = [new Uri($"ldap://127.0.0.1:{port}")] };
        using var http = new HttpClient();
        var checker = new RevocationChecker(new OcspClient(http), new CrlClient(http) { OutboundPolicy = policy });

        await Should.ThrowAsync<RevocationCheckException>(
            () => checker.CheckRevocationAsync(pki.Leaf, pki.Chain(), [], CancellationToken.None));

        listener.Pending().ShouldBeFalse();
    }
}
