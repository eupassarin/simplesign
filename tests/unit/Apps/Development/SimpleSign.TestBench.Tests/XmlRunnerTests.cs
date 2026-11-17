using Shouldly;
using SimpleSign.TestBench.Runs;
using SimpleSign.TestBench.Signing;
using SimpleSign.TestBench.Xml;

namespace SimpleSign.TestBench.Tests;

/// <summary>XAdES through the TestBench, against the real library.</summary>
[Collection(TestBenchCollection.Name)]
[Trait("Category", "Unit")]
public sealed class XmlRunnerTests(TestBenchFixture fixture)
{
    private XmlSample Sample(string id) => fixture.XmlSamples.Single(s => s.Id == id);

    private XmlOptions Xades(string signer = "rsa-2048") => new() { DataId = Sample("order").FileId, CredentialId = fixture.Sandboxed(signer) };

    private static string Errors(XmlSignResult r) =>
        string.Join("; ", r.Issues.Select(i => i.Message).Concat(r.Validation?.Signatures.SelectMany(s => s.Errors) ?? []).Concat(r.Validation?.Errors ?? []).Append(r.Error ?? ""));

    [SkippableTheory]
    [InlineData(XadesFormChoice.Enveloped, BaselineLevel.BB)]
    [InlineData(XadesFormChoice.Detached, BaselineLevel.BT)]
    [InlineData(XadesFormChoice.Enveloping, BaselineLevel.BLT)]
    [InlineData(XadesFormChoice.Enveloped, BaselineLevel.BLTA)]
    public async Task RunAsync_Xades_IsValid(XadesFormChoice form, BaselineLevel level)
    {
        var result = await fixture.Xml.RunAsync(Xades() with { Form = form, Level = level }, default);

        result.Success.ShouldBeTrue(Errors(result));
        result.Validation!.Overall.ShouldBe("Valid", Errors(result));
        result.Validation.SignatureXml.ShouldNotBeNull();
    }

    [SkippableFact]
    public async Task RunAsync_ProductionPlace_IsInTheSignatureAndTheCode()
    {
        var options = Xades() with { PlaceCity = "Recife", PlaceState = "PE", PlaceCountry = "BR", PlaceStreet = " " };

        var result = await fixture.Xml.RunAsync(options, default);

        result.Success.ShouldBeTrue(Errors(result));
        result.Validation!.Overall.ShouldBe("Valid", Errors(result));
        string signatureXml = result.Validation.SignatureXml.ShouldNotBeNull();
        signatureXml.ShouldContain("SignatureProductionPlaceV2");
        signatureXml.ShouldContain("Recife");
        signatureXml.ShouldNotContain("StreetAddress");
        result.Code.CSharp.ShouldContain(".WithSignatureProductionPlace(new SignatureProductionPlace { City = \"Recife\", StateOrProvince = \"PE\", CountryName = \"BR\" })");
        result.Code.Cli.ShouldContain("--place-city Recife");
        result.Code.Cli.ShouldContain("--place-state PE");
        result.Code.Cli.ShouldNotContain("--place-street");
    }

    [SkippableFact]
    public async Task RunAsync_CrlFirstAtLongTerm_IsValidAndInTheCode()
    {
        var options = Xades() with { Level = BaselineLevel.BLT, RevocationPreference = SimpleSign.Core.Signing.RevocationPreference.CrlFirst };

        var result = await fixture.Xml.RunAsync(options, default);

        result.Success.ShouldBeTrue(Errors(result));
        result.Validation!.Overall.ShouldBe("Valid", Errors(result));
        result.Code.CSharp.ShouldContain("{ RevocationPreference = RevocationPreference.CrlFirst }");
        result.Code.Cli.ShouldContain("--revocation-preference crl");
    }

    [SkippableTheory]
    [InlineData(XadesFormChoice.Enveloped, BaselineLevel.BB)]
    [InlineData(XadesFormChoice.Enveloping, BaselineLevel.BT)]
    [InlineData(XadesFormChoice.Enveloped, BaselineLevel.BLTA)]
    public async Task RunAsync_InclusiveCanonicalization_IsValidAndInTheCode(XadesFormChoice form, BaselineLevel level)
    {
        var options = Xades() with { Form = form, Level = level, Canonicalization = SimpleSign.XAdES.XadesCanonicalization.Inclusive };

        var result = await fixture.Xml.RunAsync(options, default);

        result.Success.ShouldBeTrue(Errors(result));
        result.Validation!.Overall.ShouldBe("Valid", Errors(result));
        string signatureXml = result.Validation.SignatureXml.ShouldNotBeNull();
        signatureXml.ShouldContain("<CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"");
        result.Code.CSharp.ShouldContain(".WithCanonicalization(XadesCanonicalization.Inclusive)");
        result.Code.Cli.ShouldContain("--canonicalization inclusive");
    }

    [SkippableTheory]
    [InlineData(BaselineLevel.BB)]
    [InlineData(BaselineLevel.BLTA)]
    public async Task RunAsync_CustomPolicyWithDocument_EmbedsThePolicyStore(BaselineLevel level)
    {
        var policy = fixture.Documents.Add("policy.xml", "<policy>a signature policy document</policy>"u8.ToArray());
        var options = Xades() with { Kind = XadesKind.CustomPolicy, Level = level, PolicyDocumentId = policy.Id, PolicySpecification = "https://example.com/policy-syntax" };

        var result = await fixture.Xml.RunAsync(options, default);

        result.Success.ShouldBeTrue(Errors(result));
        result.Validation!.Overall.ShouldBe("Valid", Errors(result));
        string signatureXml = result.Validation.SignatureXml.ShouldNotBeNull();
        signatureXml.ShouldContain("SignaturePolicyStore");
        signatureXml.ShouldContain("https://example.com/policy-syntax");
        result.Code.CSharp.ShouldContain(".WithSignaturePolicyStore(SignaturePolicyStore.FromDocument(\"https://example.com/policy-syntax\", policyDocument))");
        result.Code.Cli.ShouldContain("--policy-document policy.xml");
        result.Code.Cli.ShouldContain("--policy-specification https://example.com/policy-syntax");
    }

    [SkippableTheory]
    [InlineData(XadesFormChoice.Enveloped, BaselineLevel.BB)]
    [InlineData(XadesFormChoice.Enveloping, BaselineLevel.BT)]
    [InlineData(XadesFormChoice.Detached, BaselineLevel.BLTA)]
    public async Task RunAsync_DataObjectsTimestamp_IsSignedValidatedAndInTheCode(XadesFormChoice form, BaselineLevel level)
    {
        var options = Xades() with { Form = form, Level = level, DataObjectsTimestamp = true, DataUri = "pedido.xml" };

        var result = await fixture.Xml.RunAsync(options, default);

        result.Success.ShouldBeTrue(Errors(result));
        result.Validation!.Overall.ShouldBe("Valid", Errors(result));
        result.Validation.SignatureXml.ShouldNotBeNull().ShouldContain("AllDataObjectsTimeStamp");
        result.Validation.Signatures[0].Checks.ShouldContain(c => c.Id == "dataObjectsTimestamp" && c.Status == "pass");
        result.Code.CSharp.ShouldContain(".WithDataObjectsTimestamp(tsa)");
    }

    [SkippableTheory]
    [InlineData(BaselineLevel.BB)]
    [InlineData(BaselineLevel.BT)]
    public async Task RunAsync_CounterSign_AddsACounterSignatureUnderTheSignature(BaselineLevel level)
    {
        var signed = await fixture.Xml.RunAsync(Xades(), default);
        signed.Success.ShouldBeTrue(Errors(signed));
        var options = Xades("rsa-3072") with { DataId = signed.OutputId, CounterSign = true, Level = level, SignerRoles = ["Testemunha"] };

        var result = await fixture.Xml.RunAsync(options, default);

        result.Success.ShouldBeTrue(Errors(result));
        result.Validation!.Overall.ShouldBe("Valid", Errors(result));
        result.Validation.Signatures.Count.ShouldBe(2);
        result.Validation.Signatures[0].Indication.ShouldBe("Valid");
        result.Validation.Signatures[1].Indication.ShouldBe("Valid");
        result.Validation.Signatures[1].Reference.ShouldNotBeNull().ShouldContain(result.Validation.Signatures[0].Reference!);
        result.Validation.Signatures[1].Level.ShouldBe(level == BaselineLevel.BB ? "B-B" : "B-T");
        result.Code.CSharp.ShouldContain("XadesSigner.CounterSign(xml)");
        result.Code.Cli.ShouldContain("simplesign xades sign signed.xml");
        result.Code.Cli.ShouldContain("--countersign");
    }

    [SkippableTheory]
    [InlineData(RunEngines.Library, XadesFormChoice.Enveloped, BaselineLevel.BB)]
    [InlineData(RunEngines.Library, XadesFormChoice.Detached, BaselineLevel.BT)]
    [InlineData(RunEngines.Library, XadesFormChoice.Enveloping, BaselineLevel.BLTA)]
    [InlineData(RunEngines.Cli, XadesFormChoice.Enveloped, BaselineLevel.BT)]
    [InlineData(RunEngines.Cli, XadesFormChoice.Detached, BaselineLevel.BLT)]
    public async Task RunAsync_TwoPhases_IsValidAndShowsTheThreePhases(string engine, XadesFormChoice form, BaselineLevel level)
    {
        var options = Xades() with { TwoPhases = true, Form = form, Level = level, SignerRoles = ["Diretor"] };

        var result = await fixture.Xml.RunAsync(options, engine, default);

        result.Success.ShouldBeTrue(Errors(result) + string.Join("; ", result.Cli?.Select(c => c.Output) ?? []));
        result.Validation!.Overall.ShouldBe("Valid", Errors(result));
        result.AchievedLevel.ShouldBe(result.RequestedLevel);
        result.Code.CSharp.ShouldContain("XadesDeferredSigner.Document(xml)");
        result.Code.CSharp.ShouldContain("XadesDeferredSigner.Resume(prepared.SessionData, sessionIntegrityKey)");
        result.Code.CSharp.ShouldContain(".CompleteWithDetailsAsync(signature)");
        result.Code.CSharp.ShouldNotContain("XadesSigner.Document");
        result.Code.Cli.ShouldContain("simplesign xades sign document.xml");
        result.Code.Cli.ShouldContain("--prepare");
        result.Code.Cli.ShouldContain("simplesign deferred complete document.xml.session");
    }

    [SkippableTheory]
    [InlineData(RunEngines.Library)]
    [InlineData(RunEngines.Cli)]
    public async Task RunAsync_TwoPhasesCounterSign_AddsACounterSignatureUnderTheSignature(string engine)
    {
        var signed = await fixture.Xml.RunAsync(Xades(), default);
        signed.Success.ShouldBeTrue(Errors(signed));
        var options = Xades("rsa-3072") with { TwoPhases = true, DataId = signed.OutputId, CounterSign = true, Level = BaselineLevel.BT };

        var result = await fixture.Xml.RunAsync(options, engine, default);

        result.Success.ShouldBeTrue(Errors(result) + string.Join("; ", result.Cli?.Select(c => c.Output) ?? []));
        result.Validation!.Overall.ShouldBe("Valid", Errors(result));
        result.Validation.Signatures.Count.ShouldBe(2);
        result.Validation.Signatures[1].Level.ShouldBe("B-T");
        result.Code.CSharp.ShouldContain("XadesDeferredSigner.CounterSign(xml)");
        result.Code.Cli.ShouldContain("simplesign deferred complete signed.xml.session");
    }

    [SkippableFact]
    public async Task RunAsync_CounterSignDocumentWithoutSignature_IsRefused()
    {
        var result = await fixture.Xml.RunAsync(Xades() with { CounterSign = true }, default);

        result.Success.ShouldBeFalse();
        result.Issues.ShouldContain(i => i.Severity == IssueSeverity.Error);
    }

    [SkippableTheory]
    [InlineData(XadesFormChoice.Enveloped, BaselineLevel.BB)]
    [InlineData(XadesFormChoice.Detached, BaselineLevel.BLTA)]
    public async Task RunAsync_AdditionalDataObjects_AreSignedAndValidated(XadesFormChoice form, BaselineLevel level)
    {
        var attachment = fixture.Documents.Add("anexo.bin", [0x25, 0x50, 0x44, 0x46, 0x00, 0xFF]);
        var terms = fixture.Documents.Add("termos.txt", "Termos e condições"u8.ToArray());
        var options = Xades() with { Form = form, Level = level, DataUri = "pedido.xml", EmbeddedObjectId = attachment.Id, ExternalObjectId = terms.Id, DataObjectsTimestamp = true };

        var result = await fixture.Xml.RunAsync(options, default);

        result.Success.ShouldBeTrue(Errors(result));
        result.Validation!.Overall.ShouldBe("Valid", Errors(result));
        string signatureXml = result.Validation.SignatureXml.ShouldNotBeNull();
        signatureXml.ShouldContain("URI=\"termos.txt\"");
        signatureXml.ShouldContain("http://www.w3.org/2000/09/xmldsig#base64");
        result.Code.CSharp.ShouldContain(".WithAdditionalDataObject(XadesDataObject.Embedded(attachment))");
        result.Code.CSharp.ShouldContain(".WithAdditionalDataObject(XadesDataObject.External(\"termos.txt\", externalFile))");
        result.Code.Cli.ShouldContain("--embed-object anexo.bin");
        result.Code.Cli.ShouldContain("--external-object termos.txt=termos.txt");
        result.Code.Cli.ShouldContain("--data-objects-timestamp");
        // Without the external file the same signature cannot be verified.
        (await fixture.Xml.ValidateAsync(result.OutputId!, form == XadesFormChoice.Detached ? options.DataId : null, new SimpleSign.TestBench.Validation.ValidationSettings()))
            .Overall.ShouldNotBe("Valid");
    }

    [SkippableFact]
    public async Task RunAsync_CertifiedRoleAndSignedAssertion_AreInSignerRoleV2()
    {
        // Any single DER SEQUENCE stands for the attribute certificate: the library embeds it as given.
        var attributeCertificate = fixture.Documents.Add("role.ac", [0x30, 0x03, 0x04, 0x01, 0xAA]);
        var assertion = fixture.Documents.Add("assertion.xml", "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"a1\"/>"u8.ToArray());
        var options = Xades() with { SignerRoles = ["Diretor"], AttributeCertificateId = attributeCertificate.Id, SignedAssertionId = assertion.Id };

        var result = await fixture.Xml.RunAsync(options, default);

        result.Success.ShouldBeTrue(Errors(result));
        result.Validation!.Overall.ShouldBe("Valid", Errors(result));
        string signatureXml = result.Validation.SignatureXml.ShouldNotBeNull();
        signatureXml.ShouldContain("SignerRoleV2");
        signatureXml.ShouldContain("X509AttributeCertificate");
        signatureXml.ShouldContain("SignedAssertion");
        result.Code.CSharp.ShouldContain(".WithAttributeCertificates([attributeCertificate])");
    }

    [SkippableFact]
    public async Task RunAsync_Xades132FormWithAttributeCertificate_LeavesItOut()
    {
        var attributeCertificate = fixture.Documents.Add("role.ac", [0x30, 0x03, 0x04, 0x01, 0xAA]);
        var options = Xades() with { SigningCertificateV1 = true, SignerRoles = ["Diretor"], AttributeCertificateId = attributeCertificate.Id };

        var result = await fixture.Xml.RunAsync(options, default);

        // The rules switch the option off for the XAdES 1.3.2 form, which keeps the legacy SignerRole.
        result.Success.ShouldBeTrue(Errors(result));
        string signatureXml = result.Validation!.SignatureXml.ShouldNotBeNull();
        signatureXml.ShouldNotContain("SignerRoleV2");
        signatureXml.ShouldNotContain("X509AttributeCertificate");
    }

    [SkippableFact]
    public async Task RunAsync_XadesDetails_AreInTheSignatureAndTheCode()
    {
        var options = Xades() with { SignerRoles = ["Gerente"], MimeType = "text/xml", Commitment = "ProofOfOrigin", Hash = HashChoice.Sha512, Padding = RsaPadding.Pss, Form = XadesFormChoice.Detached, DataUri = "pedido.xml" };

        var result = await fixture.Xml.RunAsync(options, default);

        result.Success.ShouldBeTrue(Errors(result));
        result.Validation!.Overall.ShouldBe("Valid", Errors(result));
        result.Validation.SignatureXml!.ShouldContain("ClaimedRole");
        result.Code.CSharp.ShouldContain(".WithSignerRoles([\"Gerente\"])");
        result.Code.Cli.ShouldContain("--form detached");
        result.Code.Cli.ShouldContain("--data-uri pedido.xml");
    }

    [SkippableTheory]
    [InlineData("v-xades")]
    [InlineData("v-detached")]
    [InlineData("v-changed")]
    [InlineData("v-tampered")]
    [InlineData("v-untrusted")]
    public async Task Validate_Sample_MatchesItsExpectedResult(string id)
    {
        var sample = Sample(id);

        var view = await fixture.Xml.ValidateAsync(sample.FileId, sample.DataId, new SimpleSign.TestBench.Validation.ValidationSettings());

        view.Overall.ShouldBe(sample.ExpectedIndication, string.Join("; ", view.Signatures.SelectMany(s => s.Errors).Concat(view.Errors)));
        if (sample.ExpectedCheck is { } check and not "—")
        {
            view.Signatures[0].Checks.Single(c => c.Id == check).Status.ShouldBe("fail");
        }
    }
}
