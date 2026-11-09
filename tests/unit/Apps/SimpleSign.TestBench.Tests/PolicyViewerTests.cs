using System.Globalization;
using Shouldly;
using SimpleSign.Core.Policies;
using SimpleSign.TestBench.Policies;

namespace SimpleSign.TestBench.Tests;

/// <summary>The policy viewer explains every element of the policies and says which ones SimpleSign evaluates.</summary>
[Collection(TestBenchCollection.Name)]
[Trait("Category", "Unit")]
public sealed class PolicyViewerTests(TestBenchFixture fixture)
{
    private static IEnumerable<PolicyNodeView> All(PolicyNodeView node) => node.Children.SelectMany(All).Prepend(node);

    private PolicyView View(PolicyViewRequest request) => PolicyViewer.View(request, fixture.Documents);

    [SkippableFact]
    public void View_DefaultSigningPolicy_EveryConstraintIsEvaluated()
    {
        var view = View(new PolicyViewRequest(PolicyViewer.Signing));

        view.Error.ShouldBeNull();
        view.Kind.ShouldBe(PolicyViewer.Signing);
        view.Name.ShouldBe(SigningPolicy.Default.Name);
        view.Digest.ShouldBe(SigningPolicy.Default.Digest);
        All(view.Root!).Where(n => n.Kind != "section").ShouldAllBe(n => n.Evaluation == "evaluated");
        var keyUsage = All(view.Root!).Single(n => n.Path == "SigningCertificate/KeyUsage");
        keyUsage.Level.ShouldBe("FAIL");
        keyUsage.Ids.ShouldBe(["digitalSignature", "nonRepudiation"]);
    }

    [SkippableFact]
    public void View_DefaultValidationPolicy_ReadsLevelsValuesAndAlgorithms()
    {
        var view = View(new PolicyViewRequest());

        view.Error.ShouldBeNull();
        var nodes = All(view.Root!).ToDictionary(n => n.Path);
        var keyUsage = nodes["SignatureConstraints/BasicSignatureConstraints/SigningCertificate/KeyUsage"];
        keyUsage.Level.ShouldBe("WARN");
        keyUsage.Ids.ShouldBe(["nonRepudiation"]);
        keyUsage.Evaluation.ShouldBe("evaluated");
        keyUsage.Standard.ShouldNotBeNull();
        nodes["SignatureConstraints/BasicSignatureConstraints/ByteRange"].Evaluation.ShouldBe("evaluated");
        nodes["SignatureConstraints/BasicSignatureConstraints/PdfSignatureDictionary"].Evaluation.ShouldBe("evaluated");
        nodes["SignatureConstraints/BasicSignatureConstraints/DocMDP"].Evaluation.ShouldBe("evaluated");
        nodes["SignatureConstraints/StructuralValidation"].Evaluation.ShouldBe("toImplement");
        nodes["Revocation/UnknownStatus"].Evaluation.ShouldBe("evaluated");
        nodes["Timestamp/Coherence"].Evaluation.ShouldBe("evaluated");
        nodes["TrustedLists/TLVersion"].Evaluation.ShouldBe("evaluated");
        nodes.Keys.ShouldNotContain("ContainerConstraints");
        nodes.Keys.ShouldNotContain("SignatureConstraints/BasicSignatureConstraints/SigningCertificate/SunsetDate");
        nodes["Model"].Attributes["Value"].ShouldBe("SHELL");
        var expiration = nodes["Cryptographic/AlgoExpirationDate"];
        expiration.Evaluation.ShouldBe("evaluated");
        expiration.Algorithms.ShouldContain(a => a.Name == "SHA1" && a.Date == "2012-08-01");
        expiration.Algorithms.ShouldContain(a => a.Name == "RSA" && a.Size == 3000);
        view.Counts!.Evaluated.ShouldBeGreaterThan(0);
        view.Counts.ToConnect.ShouldBe(0); // Every kept constraint of the default policy is wired; only "to implement" remain.
        view.Counts.ToImplement.ShouldBeGreaterThan(0);
    }

    [SkippableFact]
    public void View_DefaultPolicies_EveryElementHasItsOwnExplanation()
    {
        var unexplained = new[] { View(new PolicyViewRequest(PolicyViewer.Signing)), View(new PolicyViewRequest()) }
            .SelectMany(v => All(v.Root!))
            .Where(n => PolicyGuide.Of(n.Name) is null)
            .Select(n => n.Path)
            .Distinct();

        unexplained.ShouldBeEmpty();
    }

    [SkippableFact]
    public void View_PortugueseCulture_ExplainsInPortuguese()
    {
        var previous = CultureInfo.CurrentUICulture;
        CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("pt-BR");
        try
        {
            var view = View(new PolicyViewRequest(PolicyViewer.Signing));

            All(view.Root!).Single(n => n.Path == "SigningCertificate/NotExpired").Explanation.ShouldStartWith("O certificado");
            view.Levels["IGNORE"].ShouldBe("A verificação não é feita.");
        }
        finally
        {
            CultureInfo.CurrentUICulture = previous;
        }
    }

    [SkippableFact]
    public void View_JsonOfTheOtherKind_IsShownAsThatKind()
    {
        var view = View(new PolicyViewRequest(PolicyViewer.Signing, ValidationPolicy.Default.WithName("Mine").ToJson()));

        view.Kind.ShouldBe(PolicyViewer.Validation);
        view.Name.ShouldBe("Mine");
    }

    [SkippableFact]
    public void View_ChangedLevel_IsRead()
    {
        string json = SigningPolicy.Default.With("SigningCertificate/NotRevoked", new PolicyConstraint(ConstraintLevel.Fail)).ToJson();

        var view = View(new PolicyViewRequest(PolicyViewer.Signing, json));

        All(view.Root!).Single(n => n.Path == "SigningCertificate/NotRevoked").Level.ShouldBe("FAIL");
    }

    [SkippableFact]
    public void View_UnknownName_ReturnsTheErrorAndKeepsTheText()
    {
        const string Json = """{ "SigningConstraints": { "Bogus": { "Level": "FAIL" } } }""";

        var view = View(new PolicyViewRequest(PolicyViewer.Signing, Json));

        view.Error.ShouldNotBeNull();
        view.Error.ShouldContain("Bogus");
        view.Root.ShouldBeNull();
        view.Json.ShouldBe(Json);
    }

    [SkippableFact]
    public void View_Upload_IsRead()
    {
        string id = fixture.UploadPolicy(SigningPolicy.Default.WithName("Uploaded").ToJson());

        View(new PolicyViewRequest(UploadId: id)).Name.ShouldBe("Uploaded");
    }
}

