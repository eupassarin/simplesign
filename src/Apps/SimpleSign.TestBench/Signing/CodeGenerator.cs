using System.Globalization;
using System.Text;
using SimpleSign.TestBench.Credentials;

namespace SimpleSign.TestBench.Signing;

/// <summary>
/// Prints the C# (the same builder calls the runner made) and the equivalent <c>simplesign sign</c>
/// command. Secrets are never printed: passwords, PINs and tokens appear as variables.
/// </summary>
internal static class CodeGenerator
{
    public static CodeSnippets Generate(SigningOptions o, SigningPlan plan, IReadOnlyList<PlanStep> steps, CredentialFacts credential)
    {
        var (cli, notes) = Cli(o, credential);
        return new CodeSnippets(CSharp(o, plan, steps), cli, notes);
    }

    private static string CSharp(SigningOptions o, SigningPlan plan, IReadOnlyList<PlanStep> steps)
    {
        var sb = new StringBuilder();
        sb.Append("using SimpleSign.PAdES;\nusing SimpleSign.PAdES.Signing;\nusing SimpleSign.Core.Signing;\n");
        if (o.Kind == SignatureKind.IcpBrasil || o.UseSignerDetails && o.SignerDetails == SignerDetailsKind.Aea || o.Health.Enabled)
        {
            sb.Append("using SimpleSign.Brazil.IcpBrasil;\nusing SimpleSign.Brazil.Signing;\n");
        }

        sb.Append('\n');
        if (plan.IsSandbox)
        {
            sb.Append("// Sandbox: sandboxHttp is an IHttpClientProvider that answers *.sandbox.simplesign.test (TSA and CRLs).\n");
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
                Deferred(sb, plan);
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

    private static void Deferred(StringBuilder sb, SigningPlan plan)
    {
        sb.Append("// Phase 1 — server: prepare the PDF and get the hash to sign.\n");
        sb.Append("byte[] sessionIntegrityKey = RandomNumberGenerator.GetBytes(32); // keep it server-side\n");
        sb.Append("var prepared = await DeferredSigner.Document(pdf)\n");
        sb.Append("    .WithCertificate(certificate, chain) // the public certificate is enough\n");
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
        sb.Append("    .WithSessionIntegrityKey(sessionIntegrityKey)\n    .PrepareAsync();\n\n");
        sb.Append("// Phase 2 — signer (browser + local agent, token, cloud…): HashToSign holds the DER signed attributes;\n");
        sb.Append("// sign them as data (the signer hashes them) and return the raw signature.\n");
        sb.Append(plan.SignatureAlgorithmOid is not null
            ? "byte[] signature = rsa.SignData(prepared.HashToSign, HashAlgorithmName." + plan.HashAlgorithm.Name + ", RSASignaturePadding.Pss);\n\n"
            : "byte[] signature = rsa.SignData(prepared.HashToSign, HashAlgorithmName." + plan.HashAlgorithm.Name + ", RSASignaturePadding.Pkcs1);\n" +
              "// ECDSA: ecdsa.SignData(prepared.HashToSign, hash, DSASignatureFormat.Rfc3279DerSequence)\n" +
              "// Token / PSC / CSC: await externalSigner.SignAsync(new ExternalSigningRequest(prepared.HashToSign, hash, prepared.SignatureAlgorithmOid, ExternalSigningPayloadKind.CmsSignedAttributes), ct)\n\n");
        sb.Append("// Phase 3 — server: resume and embed the signature (timestamps and LTV are added here).\n");
        sb.Append("byte[] signed = await DeferredSigner.Resume(prepared.SessionData, sessionIntegrityKey)\n");
        if (plan.IsSandbox)
        {
            sb.Append("    .WithHttpClientProvider(sandboxHttp)\n");
        }

        if (plan.Timestamp?.Authorization is not null || plan.Timestamp?.ClientCertificate is not null)
        {
            sb.Append("    .WithTimestampOptions(tsa) // secrets are not stored in the session\n");
        }

        sb.Append("    .CompleteAsync(signature);\n");
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

    private static (string Command, IReadOnlyList<string> Notes) Cli(SigningOptions o, CredentialFacts credential)
    {
        var args = new List<string> { "simplesign sign document.pdf", "--output signed.pdf" };
        var notes = new List<string>();
        CliCredential(credential, args, notes);

        bool needsTsa = o.Kind == SignatureKind.IcpBrasil ? o.IcpPolicy != IcpPolicyKind.AdRb || o.IcpAdRbTimestamp : o.Level != BaselineLevel.BB;
        if (needsTsa)
        {
            args.Add("--tsa " + (o.Timestamp.Provider switch
            {
                TsaProvider.DigiCert => "http://timestamp.digicert.com",
                TsaProvider.Sectigo => "http://timestamp.sectigo.com",
                TsaProvider.FreeTsa => "https://freetsa.org/tsr",
                TsaProvider.Custom => o.Timestamp.Url,
                _ => "<tsa-url>",
            }));
            if (o.Timestamp.Auth != TsaAuth.None)
            {
                notes.Add("The CLI has no TSA authentication flags: use the library for authenticated TSAs.");
            }
        }

        if (o.Kind == SignatureKind.IcpBrasil)
        {
            args.Add("--icp-policy " + o.IcpPolicy.ToString().ToLowerInvariant().Replace("ad", "ad-", StringComparison.Ordinal));
            if (o.IcpVersionOid is not null)
            {
                notes.Add("The CLI always picks the policy version by the signer's root; a fixed version needs the library.");
            }
        }
        else
        {
            if (o.Level >= BaselineLevel.BLT)
            {
                args.Add("--ltv");
            }

            if (o.Level == BaselineLevel.BLTA)
            {
                args.Add("--archival");
            }

            if (o.Level >= BaselineLevel.BLT && o.RevocationPreference == Core.Signing.RevocationPreference.CrlFirst)
            {
                args.Add("--revocation-preference crl");
            }

            if (o.Kind == SignatureKind.CustomPolicy)
            {
                args.Add($"--policy-oid {o.CustomPolicy.Oid}");
                if (!string.IsNullOrWhiteSpace(o.CustomPolicy.Uri))
                {
                    args.Add($"--policy-uri {o.CustomPolicy.Uri}");
                }

                notes.Add("The CLI's --policy-oid writes the policy through the metadata; the policy hash needs the library.");
            }

            if (o.SubFilter == SubFilterChoice.AdbePkcs7Detached)
            {
                args.Add("--sub-filter adbe.pkcs7.detached");
            }
        }

        if (o.Hash != HashChoice.Sha256)
        {
            args.Add("--hash " + SigningPlan.HashName(o.Hash));
        }

        if (o.Padding == RsaPadding.Pss && credential.KeyAlgorithm == "RSA")
        {
            args.Add("--signature-algorithm rsa-pss");
        }

        if (o.FieldMode == FieldMode.Existing)
        {
            args.Add($"--existing-field \"{o.ExistingFieldName}\"");
        }
        else if (o.FieldName != "Signature1")
        {
            args.Add($"--field-name \"{o.FieldName}\"");
        }

        AddIf(args, "--reason", o.Reason);
        AddIf(args, "--location", o.Location);
        AddIf(args, "--contact", o.ContactInfo);
        AddIf(args, "--signer-name", o.SignerName);
        if (o.Certification != CertificationChoice.None)
        {
            args.Add("--certify " + o.Certification switch
            {
                CertificationChoice.NoChanges => "1",
                CertificationChoice.FormFilling => "2",
                _ => "3",
            });
        }

        if (o.PreservePdfA)
        {
            args.Add("--pdfa");
        }

        var a = o.Appearance;
        if (a.Visible)
        {
            args.Add("--visible");
            if (o.FieldMode == FieldMode.New && !a.AutoPosition)
            {
                args.Add(string.Create(CultureInfo.InvariantCulture, $"--page {a.Page} --pos-x {a.X:0.##} --pos-y {a.Y:0.##} --stamp-width {a.Width:0.##} --stamp-height {a.Height:0.##}"));
            }

            if (!a.ShowDate)
            {
                args.Add("--no-date");
            }

            AddIf(args, "--text-align", a.TextAlignment == "Left" ? null : a.TextAlignment.ToLowerInvariant());
            AddIf(args, "--signed-by-label", a.SignedByLabel);
            AddIf(args, "--reason-label", a.ReasonLabel);
            AddIf(args, "--location-label", a.LocationLabel);
            AddIf(args, "--date-label", a.DateLabel);
            AddIf(args, "--date-format", a.DateFormat);
            AddIf(args, "--time-zone", a.TimeZoneId);
            AddIf(args, "--background-color", a.BackgroundColor);
            AddIf(args, "--text-color", a.TextColor);
            AddIf(args, "--border-color", a.BorderColor);
            AddIf(args, "--font", a.BaseFont == "Helvetica" ? null : a.BaseFont);
            AddIf(args, "--font-size", a.FontSize?.ToString(CultureInfo.InvariantCulture));
            AddIf(args, "--label-font-size", a.LabelFontSize?.ToString(CultureInfo.InvariantCulture));
            AddIf(args, "--qr-url", a.VerificationUrl);
            if (a.ImageUploadId is not null)
            {
                args.Add("--background-image stamp.png");
                AddIf(args, "--image-fit", a.ImageFit.ToLowerInvariant());
            }
        }

        if (o.UseSignerDetails && o.SignerDetails == SignerDetailsKind.Aea)
        {
            args.Add("--brasil");
            AddIf(args, "--cpf", o.Aea.Cpf);
            AddIf(args, "--auth-method", o.Aea.AuthMethod);
            AddIf(args, "--signer-email", o.Aea.Email);
            AddIf(args, "--institution", o.Aea.InstitutionName);
            AddIf(args, "--institution-cnpj", o.Aea.InstitutionCnpj);
            AddIf(args, "--commitment", o.Aea.CommitmentType);
        }

        if (o.Health.Enabled)
        {
            args.Add($"--health-document {o.Health.Type}");
            foreach (var p in o.Health.Professionals)
            {
                args.Add($"--registration {p.Council}:{p.RegistrationNumber}{(p.StateCode is null ? "" : ":" + p.StateCode)}");
            }
        }

        if (o.Mode != RunMode.Sign)
        {
            notes.Add(o.Mode == RunMode.Deferred ? "Deferred signing is a library API (DeferredSigner); the CLI signs in one step." : "For batches, run the command per file or use BatchSigner.");
        }

        if (o.DocumentInfo.Count > 0 || o.UseSignerDetails && o.SignerDetails == SignerDetailsKind.Metadata || o.SigningTime is not null || o.ContentsReservedBytes is not null || o.SeparateArchiveTsa || o.ReturnLowerLevel)
        {
            notes.Add("Some options (document info, structured metadata, signing time, /Contents size, separate archive TSA, return-lower-level) have no CLI flag: use the library.");
        }

        return (string.Join(" \\\n  ", args), notes);
    }

    /// <summary>The CLI flags that pick the signer (shared by <c>sign</c>, <c>cades sign</c> and <c>xades sign</c>).</summary>
    internal static void CliCredential(CredentialFacts credential, List<string> args, List<string> notes)
    {
        switch (credential.Kind)
        {
            case CredentialKind.Pfx:
            case CredentialKind.SandboxA1:
                args.Add("--cert signer.pfx --password \"$PFX_PASSWORD\"");
                if (credential.Kind == CredentialKind.SandboxA1)
                {
                    notes.Add("The sandbox certificate exists only inside the TestBench; export your own PFX to run this.");
                }

                break;
            case CredentialKind.OsStore:
                args.Add($"--store --thumbprint {credential.Id}");
                notes.Add("Use the certificate's thumbprint from your OS store.");
                break;
            case CredentialKind.Pkcs11:
                args.Add("--pkcs11-lib /path/to/driver --thumbprint <thumbprint>");
                break;
            case CredentialKind.Psc:
                args.Add("--psc-url https://<psc>/v0/");
                break;
            case CredentialKind.Csc:
                args.Add("--csc-url https://<qtsp>/csc/v2/");
                break;
        }
    }

    internal static void AddIf(List<string> args, string flag, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            args.Add($"{flag} \"{value.Replace("\"", "\\\"", StringComparison.Ordinal)}\"");
        }
    }
}
