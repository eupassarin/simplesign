using Shouldly;
using SimpleSign.Core.Signing;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Endpoints;
using SimpleSign.TestHelpers;

namespace SimpleSign.TestBench.Tests;

/// <summary>The Envelope tab: prepare, sign in turn with the Sandbox's signers, see where it stands, validate.</summary>
[Collection(TestBenchCollection.Name)]
[Trait("Category", "Unit")]
public sealed class EnvelopeApiTests(TestBenchFixture fixture)
{
    [SkippableFact]
    public async Task PrepareSignValidate_TwoSandboxSigners_TheEnvelopeIsComplete()
    {
        fixture.RequireSandbox();
        var first = fixture.Credentials.Add(fixture.Factory.OpenSandbox(new SandboxCredentialRequest("rsa-2048")));
        var second = fixture.Credentials.Add(fixture.Factory.OpenSandbox(new SandboxCredentialRequest("ecdsa-p256")));
        var document = fixture.Documents.Add("contract.pdf", TestPdfFactory.CreateMinimalPdfWithPage());
        string tsa = fixture.Sandbox.Connection.TsaUri.AbsoluteUri;

        var prepared = await EnvelopeApi.PrepareAsync(new EnvelopePrepareRequest(document.Id, "sequential", tsa, "form-filling", false,
            [
                new EnvelopeSignerRequest("Ana", first.Id, null, null, "Diretora", null, false, "any", 1, 72, 72, 200, 50),
                new EnvelopeSignerRequest("Bruno", second.Id, null, null, null, null, false, "pades-t", 1, 72, 150, 200, 50),
            ]), fixture.Documents, fixture.Credentials, default);
        prepared.Status.ShouldBe("Prepared");
        prepared.Next.ShouldBe("SimpleSign_1");

        var notYourTurn = await Should.ThrowAsync<SigningException>(EnvelopeApi.SignAsync(
            new EnvelopeSignRequest(prepared.FileId, "SimpleSign_2", second.Id, null, tsa, null), fixture.Documents, fixture.Credentials, fixture.Sandbox, default));
        notYourTurn.Reason.ShouldBe(SigningErrorReason.NotYourTurn);

        var once = await EnvelopeApi.SignAsync(
            new EnvelopeSignRequest(prepared.FileId, "SimpleSign_1", first.Id, null, null, "form-filling"), fixture.Documents, fixture.Credentials, fixture.Sandbox, default);
        var twice = await EnvelopeApi.SignAsync(
            new EnvelopeSignRequest(once.FileId, "SimpleSign_2", second.Id, null, tsa, null), fixture.Documents, fixture.Credentials, fixture.Sandbox, default);
        twice.Status.ShouldBe("Completed");
        twice.Fields[0].ClaimedRoles.ShouldBe(["Diretora"]);

        var report = await EnvelopeApi.ValidateAsync(new EnvelopeFileRequest(twice.FileId), fixture.Documents, fixture.Sandbox, default);
        report.IsComplete.ShouldBeTrue(report.ToJson());
    }

    [Fact]
    public void Status_UnknownFile_Throws() =>
        Should.Throw<FileNotFoundException>(() => EnvelopeApi.Status(new EnvelopeFileRequest("nope"), fixture.Documents));

    [Fact]
    public void Status_NoEnvelope_Throws()
    {
        var document = fixture.Documents.Add("plain.pdf", TestPdfFactory.CreateMinimalPdfWithPage());

        Should.Throw<ArgumentException>(() => EnvelopeApi.Status(new EnvelopeFileRequest(document.Id), fixture.Documents));
    }
}
