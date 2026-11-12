using Shouldly;
using SimpleSign.TestBench.Playbooks;
using SimpleSign.TestBench.Sandbox;

namespace SimpleSign.TestBench.Tests.Playbooks;

[Trait("Category", "Unit")]
public sealed class PlaybookSchemaTests
{
    [Fact]
    public void SandboxReference_NoSandbox_ListsEveryFaultAndNoIds()
    {
        var reference = PlaybookSchema.SandboxReference(null, null);

        reference.Connected.ShouldBeFalse();
        reference.Signers.ShouldBeEmpty();
        reference.Certificates.ShouldBeEmpty();
        reference.Faults["crl"].ShouldBe(Enum.GetNames<CrlFault>());
        reference.Faults["ocsp"].ShouldBe(Enum.GetNames<OcspFault>());
        reference.Faults["tsa"].ShouldBe(Enum.GetNames<TsaFault>());
        reference.Faults["trustedList"].ShouldBe(Enum.GetNames<TlFault>());
    }

    [Fact]
    public void SandboxReference_Connected_ListsSignersAndCertificates()
    {
        var certificate = new SandboxCertificateInfo("revoked", "Revoked", "", null, null, null, null, null, true, null);

        var reference = PlaybookSchema.SandboxReference([("rsa-2048", "RSA 2048")], [certificate]);

        reference.Connected.ShouldBeTrue();
        reference.Signers.ShouldBe([new PlaybookReferenceId("rsa-2048", "RSA 2048")]);
        reference.Certificates.ShouldBe([new PlaybookReferenceId("revoked", "Revoked")]);
    }
}
