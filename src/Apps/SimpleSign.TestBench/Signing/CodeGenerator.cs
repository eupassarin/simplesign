using System.Globalization;
using System.Text;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Localization;

namespace SimpleSign.TestBench.Signing;

/// <summary>
/// Prints the C# (the same builder calls the runner made) and the equivalent <c>simplesign sign</c>
/// command. Secrets are never printed: passwords, PINs and tokens appear as variables.
/// </summary>
internal static class CodeGenerator
{
    public static CodeSnippets Generate(SigningOptions o, SigningPlan plan, IReadOnlyList<PlanStep> steps, CredentialFacts credential)
    {
        var (commands, notes) = Cli(o, plan, credential);
        return new CodeSnippets(CSharp(o, plan, steps), CliLine.Join(commands), notes) { CliCommands = commands };
    }

    private static string CSharp(SigningOptions o, SigningPlan plan, IReadOnlyList<PlanStep> steps)
    {
        var sb = new StringBuilder();
        sb.Append("using SimpleSign.PAdES;\nusing SimpleSign.PAdES.Signing;\nusing SimpleSign.Core.Signing;\n\n");
        if (plan.IsSandbox)
        {
            sb.Append("// The SimpleSign Sandbox runs on this machine: sandboxHttp (below) lets the library reach it.\n");
            sb.Append("// In production, omit it: the library uses a shared HttpClient.\n");
        }

        sb.Append("byte[] pdf = File.ReadAllBytes(\"document.pdf\");\n");
        foreach (string line in plan.Setup.Distinct())
        {
            sb.Append(line).Append('\n');
        }

        sb.Append('\n');
        switch (o.Mode)
        {
            case RunMode.Deferred:
                Deferred(sb, plan, steps);
                break;
            case RunMode.Batch:
                Batch(sb, o, plan);
                break;
            default:
                sb.Append("PadesSigningResult result = await PadesSigner.Document(pdf)\n");
                foreach (var step in steps)
                {
                    sb.Append("    ").Append(step.Code).Append('\n');
                }

                sb.Append("    .SignWithDetailsAsync();\n\n");
                sb.Append("File.WriteAllBytes(\"signed.pdf\", result.SignedArtifact);\n");
                sb.Append("Console.WriteLine($\"Requested {result.RequestedLevel}, achieved {result.AchievedLevel}\");\n");
                break;
        }

        return sb.ToString();
    }

    private static void Deferred(StringBuilder sb, SigningPlan plan, IReadOnlyList<PlanStep> steps)
    {
        sb.Append("// Phase 1 — server: every option of PadesSigner, with the public certificate. The signing policy runs here.\n");
        sb.Append("byte[] sessionIntegrityKey = RandomNumberGenerator.GetBytes(32); // keep it server-side\n");
        sb.Append("var prepared = await DeferredSigner.Document(pdf)\n");
        sb.Append("    .WithCertificate(certificate, chain) // the public certificate is enough\n");

        // The first step is the credential; the others are the builder calls of one-call signing.
        foreach (var step in steps.Skip(1))
        {
            sb.Append("    ").Append(step.Code).Append('\n');
        }

        sb.Append("    .WithSessionIntegrityKey(sessionIntegrityKey)\n    .PrepareAsync();\n\n");
        sb.Append("// Phase 2 — signer (browser + local agent, token, cloud…): DataToSign holds the DER signed attributes;\n");
        sb.Append("// sign them as data (the signer hashes them) and return the raw signature.\n");
        sb.Append(plan.SignatureAlgorithmOid is not null
            ? "byte[] signature = rsa.SignData(prepared.DataToSign, HashAlgorithmName." + plan.HashAlgorithm.Name + ", RSASignaturePadding.Pss);\n\n"
            : "byte[] signature = rsa.SignData(prepared.DataToSign, HashAlgorithmName." + plan.HashAlgorithm.Name + ", RSASignaturePadding.Pkcs1);\n" +
              "// ECDSA: ecdsa.SignData(prepared.DataToSign, hash, DSASignatureFormat.Rfc3279DerSequence)\n" +
              "// Token / CSC: await externalSigner.SignAsync(prepared.ToSigningRequest(), ct)\n\n");
        sb.Append("// Phase 3 — server (any instance): resume, verify the signature, finish the level.\n");
        sb.Append("PadesSigningResult result = await DeferredSigner.Resume(prepared.SessionData, sessionIntegrityKey)\n");
        foreach (var (code, _) in plan.ResumeSteps())
        {
            sb.Append("    ").Append(code).Append('\n');
        }

        sb.Append("    .CompleteWithDetailsAsync(signature);\n\n");
        sb.Append("File.WriteAllBytes(\"signed.pdf\", result.SignedArtifact);\n");
        sb.Append("Console.WriteLine($\"Requested {result.RequestedLevel}, achieved {result.AchievedLevel}\");\n");
    }

    private static void Batch(StringBuilder sb, SigningOptions o, SigningPlan plan)
    {
        sb.Append("await using var batch = BatchSigner.Create(certificate)\n");
        sb.Append("    .WithChain(chain)\n");
        if (plan.IsSandbox)
        {
            sb.Append("    .WithHttpClientProvider(sandboxHttp)\n");
        }

        if (plan.HashAlgorithm.Name != "SHA256")
        {
            sb.Append(CultureInfo.InvariantCulture, $"    .WithHashAlgorithm(HashAlgorithmName.{plan.HashAlgorithm.Name})\n");
        }

        if (plan.SignatureAlgorithmOid is not null)
        {
            sb.Append("    .WithSignatureAlgorithm(Oids.RsaPss)\n");
        }

        sb.Append("    .WithFieldOptions(").Append(plan.FieldCode()).Append(")\n");
        sb.Append("    .WithLevel(").Append(plan.ProfileCode()).Append(")\n");
        sb.Append(CultureInfo.InvariantCulture, $"    .WithMaxConcurrency({o.MaxConcurrency})\n");
        sb.Append("    .Build();\n\n");
        sb.Append("await foreach (var r in batch.SignAllAsync(inputs)) // IAsyncEnumerable<(string Id, byte[] PdfBytes)>\n{\n");
        sb.Append("    Console.WriteLine(r.IsSuccess ? $\"{r.Id}: {r.SignedPdf!.Length} bytes\" : $\"{r.Id}: {r.Error!.Message}\");\n}\n");
    }

    private static (IReadOnlyList<CliLine> Commands, IReadOnlyList<string> Notes) Cli(SigningOptions o, SigningPlan plan, CredentialFacts credential)
    {
        var notes = new List<string>();
        var context = plan.Context;
        switch (o.Mode)
        {
            case RunMode.Deferred:
                {
                    // The first phase is sign with --prepare: every option of sign, and the signer's certificate without its key.
                    var prepare = new CliLine("sign", CliLine.Placeholders.Input)
                        .Add("--prepare")
                        .Add("--cert", CliLine.Placeholders.SignerCertificate)
                        .Add("--chain", CliLine.Placeholders.Chain)
                        .Add("--session-key", CliLine.Placeholders.SessionKey);
                    Level(prepare, o, context);
                    if (o.Level != BaselineLevel.BB && o.ReturnLowerLevel)
                    {
                        prepare.Add("--return-lower-level");
                    }

                    Crypto(prepare, o, credential);
                    Policy(prepare, o);
                    context.Controls.Cli(prepare);
                    Field(prepare, o);
                    Stamp(prepare, o);
                    Document(prepare, o);
                    prepare.AddIf("--operation-id", o.OperationId);
                    context.CliNetwork(prepare);
                    var complete = new CliLine("deferred", "complete", CliLine.Placeholders.Input + ".session")
                        .Add("--session-key", CliLine.Placeholders.SessionKey)
                        .Add("--signature", CliLine.Placeholders.Signature)
                        .Add("--output", CliLine.Placeholders.Output);
                    if (o.Level != BaselineLevel.BB && HasTsaCredentials(o.Timestamp))
                    {
                        context.CliTimestamp(complete, o.Timestamp);
                    }

                    // The session does not carry the policy or the anchors that check the TSA: they are given again.
                    if (o.SigningPolicyId is not null && !SigningControls.ProfileSetsPolicy(o.SigningControls, o.SigningPolicyId))
                    {
                        complete.Add("--signing-policy", PolicyUploads.SigningFileName);
                    }

                    context.Controls.Cli(complete);
                    context.CliNetwork(complete);
                    notes.Add(L.T("Between the two commands, the signer hashes document.pdf.tbs and signs it; signature.bin is the raw signature."));
                    return ([prepare, complete], notes);
                }

            case RunMode.Batch:
                {
                    var batch = new CliLine("sign-dir", CliLine.Placeholders.InputFolder)
                        .Add("--output-dir", CliLine.Placeholders.OutputFolder)
                        .Add("--max-concurrency", o.MaxConcurrency.ToString(CultureInfo.InvariantCulture));
                    CliCredential(credential, batch, notes);
                    Level(batch, o, context);
                    Crypto(batch, o, credential);
                    Field(batch, o);
                    if (o.Appearance.Visible)
                    {
                        notes.Add(L.T("simplesign sign-dir draws no stamp: the CLI's --visible is on sign only."));
                    }

                    batch.AddIf("--operation-id", o.OperationId);
                    context.CliNetwork(batch);
                    return ([batch], notes);
                }

            default:
                {
                    var sign = new CliLine("sign", CliLine.Placeholders.Input).Add("--output", CliLine.Placeholders.Output);
                    CliCredential(credential, sign, notes);
                    Level(sign, o, context);
                    if (o.Level != BaselineLevel.BB && o.ReturnLowerLevel && o.Kind != SignatureKind.IcpBrasil)
                    {
                        sign.Add("--return-lower-level");
                    }

                    Crypto(sign, o, credential);
                    Policy(sign, o);
                    context.Controls.Cli(sign);
                    Field(sign, o);
                    Stamp(sign, o);
                    Document(sign, o);
                    sign.AddIf("--operation-id", o.OperationId);
                    context.CliNetwork(sign);
                    return ([sign], notes);
                }
        }
    }

    internal static bool HasTsaCredentials(TimestampChoice choice) =>
        choice.Provider == TsaProvider.SandboxAuthenticated || choice.Auth != TsaAuth.None || !string.IsNullOrEmpty(choice.ClientCertificateUploadId);

    /// <summary>The level: the TSA (and its credentials), --ltv, --archival, a separate archive TSA, the revocation source.</summary>
    private static void Level(CliLine line, SigningOptions o, PlanContext context)
    {
        if (o.Kind == SignatureKind.IcpBrasil)
        {
            // The policy sets the level (and the sub-filter): the TSA (an ACT) from AD-RT up.
            if (o.IcpPolicy != SimpleSign.Brazil.IcpBrasil.IcpBrasilPolicy.AdRb)
            {
                context.CliTimestamp(line, o.Timestamp);
            }

            line.Add("--icp-policy", o.IcpPolicy switch
            {
                SimpleSign.Brazil.IcpBrasil.IcpBrasilPolicy.AdRb => "ad-rb",
                SimpleSign.Brazil.IcpBrasil.IcpBrasilPolicy.AdRt => "ad-rt",
                SimpleSign.Brazil.IcpBrasil.IcpBrasilPolicy.AdRc => "ad-rc",
                _ => "ad-ra",
            });
            return;
        }

        if (o.Level == BaselineLevel.BB)
        {
            return;
        }

        context.CliTimestamp(line, o.Timestamp);
        if (o.Level >= BaselineLevel.BLT)
        {
            line.Add(o.Level == BaselineLevel.BLTA ? "--archival" : "--ltv");
            if (o.RevocationPreference == Core.Signing.RevocationPreference.CrlFirst)
            {
                line.Add("--revocation-preference", "crl");
            }
        }

        if (o.Level == BaselineLevel.BLTA && o.SeparateArchiveTsa)
        {
            context.CliTimestamp(line, o.ArchiveTimestamp, archive: true);
        }
    }

    /// <summary>The hash, the RSA scheme and the reserved /Contents.</summary>
    private static void Crypto(CliLine line, SigningOptions o, CredentialFacts credential)
    {
        if (o.Hash != HashChoice.Sha256)
        {
            line.Add("--hash", SigningPlan.HashName(o.Hash));
        }

        if (o.Padding == RsaPadding.Pss && credential.KeyAlgorithm == "RSA")
        {
            line.Add("--signature-algorithm", "rsassa-pss");
        }

        if (o.ContentsReservedBytes is { } size)
        {
            line.Add("--contents-size", size.ToString(CultureInfo.InvariantCulture));
        }
    }

    /// <summary>The signing policy file and an explicit signature policy.</summary>
    private static void Policy(CliLine line, SigningOptions o)
    {
        if (o.SigningPolicyId is not null && !SigningControls.ProfileSetsPolicy(o.SigningControls, o.SigningPolicyId))
        {
            line.Add("--signing-policy", PolicyUploads.SigningFileName);
        }

        if (o.Kind == SignatureKind.CustomPolicy)
        {
            line.Add("--policy-oid", o.CustomPolicy.Oid).Add("--policy-hash", o.CustomPolicy.HashHex);
            if (o.CustomPolicy.HashAlgorithm != HashChoice.Sha256)
            {
                line.Add("--policy-hash-algorithm", SigningPlan.HashName(o.CustomPolicy.HashAlgorithm));
            }

            line.AddIf("--policy-uri", o.CustomPolicy.Uri);
        }
    }

    /// <summary>The signature field: new or existing, its declared texts.</summary>
    private static void Field(CliLine line, SigningOptions o)
    {
        if (o.FieldMode == FieldMode.Existing)
        {
            line.Add("--existing-field", o.ExistingFieldName ?? "");
        }
        else if (o.FieldName != "Signature1")
        {
            line.Add("--field-name", o.FieldName);
        }

        line.AddIf("--reason", o.Reason).AddIf("--location", o.Location).AddIf("--contact", o.ContactInfo);
        line.AddIf("--signer-name", o.UseSignerDetails ? o.Metadata.SignerName ?? o.SignerName : o.SignerName);
    }

    /// <summary>
    /// The visible stamp: <c>--visible</c>, its place and size (not in an existing field, which has its own), and every
    /// setting that differs from the CLI's default. The stamp image is written as stamp.png (or .jpg) next to the PDF.
    /// </summary>
    internal static void Stamp(CliLine line, SigningOptions o)
    {
        var a = o.Appearance;
        if (!a.Visible)
        {
            return;
        }

        static string N(float v) => v.ToString("0.##", CultureInfo.InvariantCulture);
        line.Add("--visible");
        bool existing = o.FieldMode == FieldMode.Existing;
        if (!existing && !a.AutoPosition)
        {
            line.Add("--page", a.Page.ToString(CultureInfo.InvariantCulture)).Add("--pos-x", N(a.X)).Add("--pos-y", N(a.Y));
        }

        if (!existing)
        {
            line.AddIf("--stamp-width", a.Width is { } w ? N(w) : null).AddIf("--stamp-height", a.Height is { } h ? N(h) : null);
        }

        line.AddIf("--text-align", a.TextAlignment == "Left" ? null : a.TextAlignment.ToLowerInvariant())
            .AddIf("--vertical-align", a.VerticalAlignment == "Top" ? null : a.VerticalAlignment.ToLowerInvariant());
        if (!a.ShrinkToFit)
        {
            line.Add("--no-shrink-to-fit");
        }

        if (a.MaxTextLength != new PAdES.Signing.SignatureAppearance().MaxTextLength)
        {
            line.Add("--max-text-length", a.MaxTextLength.ToString(CultureInfo.InvariantCulture));
        }

        if (!a.ShowDate)
        {
            line.Add("--no-date");
        }

        // The CLI shows the reason and the location whenever they are given.
        if (!a.ShowReason && !string.IsNullOrWhiteSpace(o.Reason))
        {
            line.Add("--hide-reason");
        }

        if (!a.ShowLocation && !string.IsNullOrWhiteSpace(o.Location))
        {
            line.Add("--hide-location");
        }

        line.AddIf("--signer-display-name", Blank(a.SignerDisplayName))
            .AddIf("--signed-by-label", a.SignedByLabel).AddIf("--reason-label", a.ReasonLabel)
            .AddIf("--location-label", a.LocationLabel).AddIf("--date-label", a.DateLabel);
        foreach (string extra in a.ExtraLines.Where(l => !string.IsNullOrWhiteSpace(l)))
        {
            line.Add("--extra-line", extra);
        }

        line.AddIf("--date-format", Blank(a.DateFormat)).AddIf("--time-zone", Blank(a.TimeZoneId)).AddIf("--date-culture", Blank(a.Culture))
            .AddIf("--font", a.BaseFont == "Helvetica" ? null : a.BaseFont)
            .AddIf("--font-size", a.FontSize?.ToString(CultureInfo.InvariantCulture))
            .AddIf("--label-font-size", a.LabelFontSize?.ToString(CultureInfo.InvariantCulture))
            .AddIf("--text-color", Rgb(a.TextColor)).AddIf("--background-color", Rgb(a.BackgroundColor)).AddIf("--border-color", Rgb(a.BorderColor));
        if (Math.Abs(a.BorderWidth - 0.5f) > 0.001f)
        {
            line.Add("--border-width", N(a.BorderWidth));
        }

        line.AddIf("--qr-url", Blank(a.VerificationUrl));
        if (!string.IsNullOrEmpty(a.ImageUploadId))
        {
            line.Add("--background-image", StampImageFile).Add("--image-fit", a.ImageFit.ToLowerInvariant());
        }
    }

    /// <summary>The stamp's background image, as a generated command names it (the CLI reads PNG or JPEG by its extension).</summary>
    internal const string StampImageFile = "stamp.png";

    private static string? Blank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;

    /// <summary>A #rrggbb color as the CLI takes it: R,G,B from 0 to 1.</summary>
    private static string? Rgb(string? hex) => SigningPlan.Color(hex) is { } c
        ? string.Create(CultureInfo.InvariantCulture, $"{c.R:0.###},{c.G:0.###},{c.B:0.###}")
        : null;

    /// <summary>What only <c>sign</c> writes: sub-filter, certification, PDF/A, document info, signing time, metadata.</summary>
    private static void Document(CliLine line, SigningOptions o)
    {
        if (o.SubFilter == SubFilterChoice.AdbePkcs7Detached)
        {
            line.Add("--sub-filter", "adbe-pkcs7-detached");
        }

        if (o.Certification != CertificationChoice.None)
        {
            line.Add("--certify", o.Certification switch
            {
                CertificationChoice.NoChanges => "no-changes",
                CertificationChoice.FormFilling => "form-filling",
                _ => "annotations",
            });
        }

        if (o.PreservePdfA)
        {
            line.Add("--pdfa");
        }

        foreach (var entry in o.DocumentInfo.Where(e => !string.IsNullOrWhiteSpace(e.Key)))
        {
            line.Add("--doc-info", $"{entry.Key}={entry.Value}");
        }

        if (o.SigningTime is { } time)
        {
            line.Add("--signing-time", time.ToString("O", CultureInfo.InvariantCulture));
        }

        if (o.UseSignerDetails)
        {
            var m = o.Metadata;
            line.AddIf("--signer-id", m.SignerId).AddIf("--signer-id-type", m.SignerIdType).AddIf("--signer-email", m.Email)
                .AddIf("--ip-address", m.IpAddress).AddIf("--auth-method", m.AuthenticationMethod)
                .AddIf("--institution", m.InstitutionName).AddIf("--institution-id", m.InstitutionId)
                .AddIf("--institution-id-type", m.InstitutionIdType).AddIf("--legal-basis", m.LegalBasis)
                .Add("--commitment", Commitment(m.CommitmentType));
            if (o.Kind == SignatureKind.Baseline)
            {
                line.AddIf("--policy-oid", m.PolicyOid).AddIf("--policy-uri", m.PolicyUri);
            }
        }
    }

    /// <summary>The CLI name of an extended form (CompleteReferences → complete-references).</summary>
    internal static string ExtendedForm(string form) => form switch
    {
        "CompleteReferences" => "complete-references",
        "ExtendedLong" => "extended-long",
        _ => "archive",
    };

    /// <summary>The CLI name of a commitment type (ProofOfOrigin → origin).</summary>
    internal static string Commitment(string commitmentType) =>
        commitmentType.StartsWith("ProofOf", StringComparison.Ordinal) ? commitmentType["ProofOf".Length..].ToLowerInvariant() : commitmentType.ToLowerInvariant();

    /// <summary>The thumbprint of the credential's certificate, as <c>--thumbprint</c> takes it.</summary>
    private static string Thumbprint(CredentialFacts credential)
    {
        using var certificate = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(Convert.FromBase64String(credential.CertificateBase64));
        return certificate.Thumbprint;
    }

    /// <summary>The CLI flags that pick the signer (shared by <c>sign</c>, <c>sign-dir</c>, <c>cades sign</c> and <c>xades sign</c>).</summary>
    internal static void CliCredential(CredentialFacts credential, CliLine line, List<string> notes)
    {
        switch (credential.Kind)
        {
            case CredentialKind.Pfx:
            case CredentialKind.SandboxA1:
                line.Add("--cert", CliLine.Placeholders.SignerPfx).Add("--password", CliLine.Placeholders.PfxPassword);
                if (credential.Kind == CredentialKind.SandboxA1)
                {
                    notes.Add(L.T("The sandbox certificate exists only inside the TestBench; export your own PFX to run this."));
                }

                break;
            case CredentialKind.OsStore:
                line.Add("--thumbprint", Thumbprint(credential));
                break;
            case CredentialKind.Pkcs11:
                line.Add("--pkcs11-lib", "auto");
                break;
            case CredentialKind.Csc:
                line.Add("--csc-url", "https://<qtsp>/csc/v2/");
                break;
        }
    }
}
