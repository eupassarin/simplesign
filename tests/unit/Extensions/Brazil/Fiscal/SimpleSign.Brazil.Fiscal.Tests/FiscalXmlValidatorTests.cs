using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.XAdES;
using static SimpleSign.Brazil.Fiscal.Tests.FiscalTestSigning;

namespace SimpleSign.Brazil.Fiscal.Tests;

/// <summary>
/// The validation of eSocial and EFD-Reinf batches (<c>envioLoteEventos</c>): each event is signed alone and then put
/// in the batch, so each is validated as the document it was when signed. The certificate is a test e-CNPJ outside
/// ICP-Brasil, so only the digests, the signature values and the layout are checked.
/// </summary>
[Trait("Category", "Unit")]
public sealed class FiscalXmlValidatorTests : IDisposable
{
    private readonly X509Certificate2 _eCnpj = CreateECnpj("11222333000181");

    public void Dispose() => _eCnpj.Dispose();

    private Task<string> SignedESocialAsync(string id, string tpAmb = "2") => SignedAsync(ESocialEvent(id, tpAmb), FiscalDocumentProfile.ESocial, _eCnpj);

    [Fact]
    public async Task VerifySignatures_ESocialBatchOfSignedEvents_ValidatesEachEvent()
    {
        string batch = ESocialBatch((ESocialEventId, await SignedESocialAsync(ESocialEventId)), (ESocialEventId2, await SignedESocialAsync(ESocialEventId2)));

        var result = FiscalXmlValidator.VerifySignatures(Utf8(batch), FiscalDocumentProfile.ESocial);

        result.IsValid.ShouldBeTrue(string.Join("; ", [.. result.Errors, .. result.Signatures.SelectMany(s => s.Errors)]));
        result.Signatures.Select(s => s.BatchEventId).ShouldBe([ESocialEventId, ESocialEventId2]);
        result.Signatures.ShouldAllBe(s => s.Signature.ReferenceUri == string.Empty && s.Cnpj == "11222333000181");
    }

    [Fact]
    public async Task VerifySignatures_ReinfBatchOfSignedEvents_ValidatesEachEvent()
    {
        // The evento carries the event's own id: in the batch as a whole that Id is not unique.
        string batch = ReinfBatch((ESocialEventId, await SignedAsync(ReinfEvent(ESocialEventId), FiscalDocumentProfile.Reinf, _eCnpj)));

        var result = FiscalXmlValidator.VerifySignatures(Utf8(batch), FiscalDocumentProfile.Reinf);

        result.IsValid.ShouldBeTrue(string.Join("; ", [.. result.Errors, .. result.Signatures.SelectMany(s => s.Errors)]));
        result.Signatures.Single().BatchEventId.ShouldBe(ESocialEventId);
    }

    [Fact]
    public async Task VerifySignatures_BatchWithATamperedEvent_ReportsThatEvent()
    {
        string tampered = (await SignedESocialAsync(ESocialEventId2)).Replace("<tpAmb>2</tpAmb>", "<tpAmb>1</tpAmb>", StringComparison.Ordinal);
        string batch = ESocialBatch((ESocialEventId, await SignedESocialAsync(ESocialEventId)), (ESocialEventId2, tampered));

        var result = FiscalXmlValidator.VerifySignatures(Utf8(batch), FiscalDocumentProfile.ESocial);

        result.IsValid.ShouldBeFalse();
        result.Signatures[0].IsValid.ShouldBeTrue();
        result.Signatures[1].BatchEventId.ShouldBe(ESocialEventId2);
        result.Signatures[1].Signature.IsDigestValid.ShouldBeFalse();
    }

    [Fact]
    public async Task VerifySignatures_BatchWithAnUnsignedEvent_ReportsIt()
    {
        string batch = ESocialBatch((ESocialEventId, await SignedESocialAsync(ESocialEventId)), (ESocialEventId2, ESocialEvent(ESocialEventId2)));

        var result = FiscalXmlValidator.VerifySignatures(Utf8(batch), FiscalDocumentProfile.ESocial);

        result.IsValid.ShouldBeFalse();
        result.Signatures.Count.ShouldBe(1);
        result.Errors.ShouldBe([$"The event {ESocialEventId2} is not signed."]);
    }

    [Fact]
    public async Task VerifySignatures_SignedBatch_ReportsTheBatchSignature()
    {
        string batch = ESocialBatch((ESocialEventId, await SignedESocialAsync(ESocialEventId)));
        byte[] signedBatch = await XmlDsigSigner.Document(Utf8(batch)).WithWholeDocument().WithHashAlgorithm(HashAlgorithmName.SHA256)
            .WithSigningPolicy(Offline(FiscalDocumentProfile.ESocial)).WithCertificate(_eCnpj).SignAsync();

        var result = FiscalXmlValidator.VerifySignatures(signedBatch, FiscalDocumentProfile.ESocial);

        result.IsValid.ShouldBeFalse();
        result.Signatures.Single().IsValid.ShouldBeTrue("the event is still valid on its own");
        result.Errors.ShouldContain(e => e.Contains("The batch itself is signed", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ValidateAsync_ESocialBatch_ChecksTheChainOfEachEvent()
    {
        string batch = ESocialBatch((ESocialEventId, await SignedESocialAsync(ESocialEventId)), (ESocialEventId2, await SignedESocialAsync(ESocialEventId2)));

        var result = await new FiscalXmlValidator().ValidateAsync(Utf8(batch), FiscalDocumentProfile.ESocial, checkRevocation: false);

        result.Signatures.Count.ShouldBe(2);
        result.Signatures.ShouldAllBe(s => s.Signature.IsDigestValid && s.Signature.IsChainValid == false);
        result.Signatures.Select(s => s.BatchEventId).ShouldBe([ESocialEventId, ESocialEventId2]);
    }
}
