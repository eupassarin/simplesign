using Shouldly;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Validation;
using SimpleSign.TestBench.Signing;
using SimpleSign.TestBench.Validation;

namespace SimpleSign.TestBench.Tests;

/// <summary>The policies the user uploads as JSON reach the signer, the validator, the generated code and DSS.</summary>
[Collection(TestBenchCollection.Name)]
[Trait("Category", "Unit")]
public sealed class PolicyUploadsTests(TestBenchFixture fixture)
{
    [SkippableFact]
    public void Signing_NoUpload_IsTheDefault()
    {
        var input = PolicyUploads.Signing(null, fixture.Documents);

        input.Uploaded.ShouldBeFalse();
        input.Policy.ShouldBe(SigningPolicy.Default);
    }

    [SkippableFact]
    public void Signing_UploadedJson_IsRead()
    {
        string id = fixture.UploadPolicy(SigningPolicy.Default.WithName("Uploaded").ToJson());

        var input = PolicyUploads.Signing(id, fixture.Documents);

        input.Uploaded.ShouldBeTrue();
        input.Error.ShouldBeNull();
        input.Policy.Name.ShouldBe("Uploaded");
    }

    [SkippableFact]
    public void Signing_ValidationPolicyUploaded_ReportsTheError()
    {
        string id = fixture.UploadPolicy(ValidationPolicy.Default.ToJson());

        var input = PolicyUploads.Signing(id, fixture.Documents);

        input.Error.ShouldNotBeNull();
        input.Policy.ShouldBe(SigningPolicy.Default);
    }

    [SkippableFact]
    public void Signing_UnreadableUpload_IsACompatibilityError()
    {
        string id = fixture.UploadPolicy("{ not json");

        var report = Compatibility.Evaluate(new SigningOptions { SigningPolicyId = id }, null, null, signingPolicy: PolicyUploads.Signing(id, fixture.Documents));

        report.CanSign.ShouldBeFalse();
        report.Issues.ShouldContain(i => i.Message.Contains("signing policy", StringComparison.OrdinalIgnoreCase));
    }

    [SkippableFact]
    public async Task Signing_UploadedPolicy_GeneratesLoadCallAndCliPath()
    {
        string id = fixture.UploadPolicy(SigningPolicy.Default.WithName("Uploaded").ToJson());

        var result = await fixture.Runner.RunAsync(fixture.Options() with { Level = BaselineLevel.BB, SigningPolicyId = id }, default);

        result.Error.ShouldBeNull(string.Join("; ", result.Issues.Select(i => i.Message)));
        result.Code.CSharp.ShouldContain($".WithSigningPolicy(SigningPolicy.Load(\"{PolicyUploads.SigningFileName}\")) // Uploaded");
        result.Code.Cli.ShouldContain($"--signing-policy {PolicyUploads.SigningFileName}");
    }

    [SkippableFact]
    public async Task Signing_KeyUsageAtIgnore_SignsWithoutSigningKeyUsage()
    {
        // The default policy refuses a certificate whose key usage has no digitalSignature/nonRepudiation;
        // an uploaded policy with KeyUsage at IGNORE lets it sign.
        fixture.RequireSandbox();
        string relaxed = fixture.UploadPolicy(SigningPolicy.Default.With("SigningCertificate/KeyUsage", new PolicyConstraint(ConstraintLevel.Ignore)).ToJson());
        var options = fixture.Options(signer: "no-signing-key-usage") with { Level = BaselineLevel.BB };

        (await fixture.Runner.RunAsync(options, default)).Success.ShouldBeFalse();
        var result = await fixture.Runner.RunAsync(options with { SigningPolicyId = relaxed }, default);

        result.Success.ShouldBeTrue(result.Error ?? string.Join("; ", result.Issues.Select(i => i.Message)));
    }

    [SkippableFact]
    public async Task Validation_UploadedPolicyLevelAndStrategy_ReachTheValidatorOptions()
    {
        string id = fixture.UploadPolicy(ValidationPolicy.Default.WithName("Uploaded validation").ToJson());
        var settings = new ValidationSettings { PolicyId = id, Level = ValidationLevel.BasicSignatures, RevocationStrategy = RevocationStrategy.CrlFirst };

        var options = (await fixture.Validation.TrustAsync(settings)).Options;

        options.Policy.Name.ShouldBe("Uploaded validation");
        options.Level.ShouldBe(ValidationLevel.BasicSignatures);
        options.Verifier.RevocationStrategy.ShouldBe(RevocationStrategy.CrlFirst);
    }

    [SkippableFact]
    public void Validation_SigningPolicyUploaded_Throws()
    {
        string id = fixture.UploadPolicy(SigningPolicy.Default.ToJson());

        Should.Throw<ArgumentException>(() => PolicyUploads.Validation(id, fixture.Documents)).Message.ShouldContain("validation policy");
    }

    [SkippableFact]
    public void Validation_DefaultsLeaveTheCodeAlone()
    {
        ValidationService.PolicyOptionsCode(new ValidationSettings()).ShouldBeEmpty();
        using var sandbox = new SimpleSign.TestBench.Sandbox.SandboxEnvironment();
        var line = new CliLine("validate", "signed.pdf");
        ValidationService.ValidationCli(line, new ValidationSettings { Trust = [TrustChoice.System] }, sandbox);
        line.Args.ShouldBe(["validate", "signed.pdf"]);
    }

    [SkippableFact]
    public void Validation_ChosenSettings_AppearInTheCodeAndCli()
    {
        var settings = new ValidationSettings { PolicyId = "x", Level = ValidationLevel.LongTermData, RevocationStrategy = RevocationStrategy.CrlFirst };

        ValidationService.PolicyOptionsCode(settings).ShouldBe(
        [
            $"Policy = ValidationPolicy.Load(\"{PolicyUploads.ValidationFileName}\")",
            "Level = ValidationLevel.LongTermData",
            "Verifier = new VerifierOptions { RevocationStrategy = RevocationStrategy.CrlFirst }",
        ]);
        using var sandbox = new SimpleSign.TestBench.Sandbox.SandboxEnvironment();
        var line = new CliLine("validate", "signed.pdf");
        ValidationService.ValidationCli(line, settings with { Trust = [] }, sandbox);
        line.Args.ShouldBe(["validate", "signed.pdf", "--no-system-roots", "--policy", PolicyUploads.ValidationFileName, "--level", "lt", "--revocation-strategy", "crl-first"]);
    }
}
