using System.Security.Cryptography;
using System.Text;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Signing;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Localization;

namespace SimpleSign.TestBench.Signing;

/// <summary>
/// What the builder that resumes a two-phase signature is given again, because a session does not carry it:
/// the HTTP provider, the signing policy and anchors that check the TSA, the audit sink and the TSA with its
/// credentials. <see cref="Code"/> holds the matching builder calls.
/// </summary>
internal sealed record ResumeInputs(
    IReadOnlyList<string> Code,
    IHttpClientProvider? Http,
    SigningPolicy? Policy,
    IReadOnlyList<ITrustAnchorProvider> Anchors,
    ISignatureAuditSink? Audit,
    TimestampOptions? Timestamp);

/// <summary>
/// What the CAdES and XML pages share to sign in two phases (<c>CadesDeferredSigner</c>, <c>XadesDeferredSigner</c>):
/// the C# of the three phases, the two CLI commands, and the signer that works between them.
/// </summary>
internal static class TwoPhaseSupport
{
    /// <summary>The inputs of the resumed builder for a plan context.</summary>
    /// <param name="context">The plan context.</param>
    /// <param name="signingPolicyId">The uploaded signing policy, or null.</param>
    /// <param name="timestamp">The signature TSA when the level has one, with its credentials; null for B-B.</param>
    public static ResumeInputs Resume(PlanContext context, string? signingPolicyId, TimestampOptions? timestamp)
    {
        var code = new List<string>();
        if (context.IsSandbox)
        {
            code.Add(context.HttpCode);
        }

        var signingPolicy = PolicyUploads.Signing(signingPolicyId, context.Documents);
        var controls = context.Controls;
        bool byProfile = controls.ProfileSetsPolicy(signingPolicyId);
        if (signingPolicy.Uploaded)
        {
            code.Add(byProfile ? controls.ProfileStepCode() : PolicyUploads.SigningCode(signingPolicy));
        }

        if (controls.TrustCode(byProfile) is { } trustCode)
        {
            code.Add(trustCode);
        }

        if (controls.AuditCode() is { } auditCode)
        {
            code.Add(auditCode);
        }

        if (timestamp is not null)
        {
            code.Add(".WithTimestampOptions(tsa) // the TSA's credentials and HTTP provider are not stored in the session");
        }

        return new ResumeInputs(
            code, context.IsSandbox ? context.Http : null, signingPolicy.Uploaded ? signingPolicy.Policy : null,
            controls.Anchors, controls.Audit, timestamp);
    }

    /// <summary>The C# of the three phases.</summary>
    /// <param name="sb">Where the code goes, after the setup statements.</param>
    /// <param name="prepareEntry">The call that starts phase one, e.g. <c>CadesDeferredSigner.Document(data)</c>.</param>
    /// <param name="stepCodes">The builder calls of one-call signing, the credential first.</param>
    /// <param name="resumeEntry">The call that starts phase three, e.g. <c>CadesDeferredSigner.Resume</c>.</param>
    /// <param name="resume">What the resumed builder is given again.</param>
    /// <param name="resultType">The result type of the format.</param>
    /// <param name="dataToSign">What the data to sign is, for the comment.</param>
    /// <param name="hash">The name of the digest algorithm.</param>
    /// <param name="pss">Whether the signature is RSASSA-PSS.</param>
    public static void AppendCSharp(
        StringBuilder sb, string prepareEntry, IEnumerable<string> stepCodes, string resumeEntry, ResumeInputs resume,
        string resultType, string dataToSign, string hash, bool pss)
    {
        sb.Append("\n// Phase 1 — server: every option of one-call signing, with the public certificate. The signing policy runs here.\n");
        sb.Append("byte[] sessionIntegrityKey = RandomNumberGenerator.GetBytes(32); // keep it server-side\n");
        sb.Append("var prepared = await ").Append(prepareEntry).Append('\n');
        sb.Append("    .WithCertificate(certificate, chain) // the public certificate is enough\n");

        // The first step is the credential; the others are the builder calls of one-call signing.
        foreach (string code in stepCodes.Skip(1))
        {
            sb.Append("    ").Append(code).Append('\n');
        }

        sb.Append("    .WithSessionIntegrityKey(sessionIntegrityKey)\n    .PrepareAsync();\n\n");
        sb.Append("// Phase 2 — signer (browser + local agent, token, cloud…): DataToSign holds ").Append(dataToSign).Append(";\n");
        sb.Append("// sign it as data (the signer hashes it) and return the raw signature.\n");
        sb.Append("byte[] signature = rsa.SignData(prepared.DataToSign, HashAlgorithmName.").Append(hash)
            .Append(pss ? ", RSASignaturePadding.Pss);\n" : ", RSASignaturePadding.Pkcs1);\n");
        sb.Append("// ECDSA: ecdsa.SignData(prepared.DataToSign, hash, DSASignatureFormat.Rfc3279DerSequence)\n");
        sb.Append("// Token / CSC: await externalSigner.SignAsync(prepared.ToSigningRequest(), ct)\n\n");
        sb.Append("// Phase 3 — server (any instance): resume, verify the signature, finish the level.\n");
        sb.Append(resultType).Append(" result = await ").Append(resumeEntry).Append("(prepared.SessionData, sessionIntegrityKey)\n");
        foreach (string code in resume.Code)
        {
            sb.Append("    ").Append(code).Append('\n');
        }

        sb.Append("    .CompleteWithDetailsAsync(signature);\n\n");
    }

    /// <summary>The credential of phase one in the CLI: the signer's certificate and chain without a key, and the session key.</summary>
    public static CliLine Prepare(CliLine line) =>
        line.Add("--prepare")
            .Add("--cert", CliLine.Placeholders.SignerCertificate)
            .Add("--chain", CliLine.Placeholders.Chain)
            .Add("--session-key", CliLine.Placeholders.SessionKey);

    /// <summary>The CLI command of phase three: <c>deferred complete</c>, with what the session does not carry.</summary>
    /// <param name="input">The input of the prepare command: its session is beside it.</param>
    /// <param name="output">The signed file.</param>
    /// <param name="context">The plan context.</param>
    /// <param name="timestamp">The TSA choice when the level has a TSA; null for B-B.</param>
    /// <param name="signingPolicyId">The uploaded signing policy, or null.</param>
    /// <param name="notes">The notes shown with the commands.</param>
    public static CliLine Complete(
        string input, string output, PlanContext context, TimestampChoice? timestamp, string? signingPolicyId, List<string> notes)
    {
        var complete = new CliLine("deferred", "complete", input + ".session")
            .Add("--session-key", CliLine.Placeholders.SessionKey)
            .Add("--signature", CliLine.Placeholders.Signature)
            .Add("--output", output);
        if (timestamp is not null && CodeGenerator.HasTsaCredentials(timestamp))
        {
            context.CliTimestamp(complete, timestamp);
        }

        // The session does not carry the policy or the anchors that check the TSA: they are given again.
        if (signingPolicyId is not null && !context.Controls.ProfileSetsPolicy(signingPolicyId))
        {
            complete.Add("--signing-policy", PolicyUploads.SigningFileName);
        }

        context.Controls.Cli(complete);
        context.CliNetwork(complete);
        notes.Add(L.T("Between the two commands, the signer hashes {0}.tbs and signs it; signature.bin is the raw signature.", input));
        return complete;
    }

    /// <summary>
    /// The signer that is elsewhere, for a run through the CLI: before <c>deferred complete</c>, signs with the
    /// credential's key the data to sign the prepare command wrote.
    /// </summary>
    public static Func<CliLine, string, CancellationToken, Task> SignOutside(CredentialHandle credential, string input, HashAlgorithmName hash, bool pss) =>
        async (command, dir, cancellationToken) =>
        {
            if (command.Args is not ["deferred", "complete", ..])
            {
                return;
            }

            byte[] toSign = await File.ReadAllBytesAsync(Path.Combine(dir, input + ".tbs"), cancellationToken);
            await File.WriteAllBytesAsync(
                Path.Combine(dir, CliLine.Placeholders.Signature), SigningRunner.SignWithLocalKey(credential, toSign, hash, pss), cancellationToken);
        };
}
