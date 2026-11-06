using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Signing;

namespace SimpleSign.Core.Validation.Policy;

/// <summary>
/// The revocation step shared by validators that do not check revocation themselves: the signer chain and the
/// signature timestamp's TSA chain, through an <see cref="IChainRevocationChecker"/>, then a new evaluation.
/// The returned warnings are those of the revocation checks only: the evaluation's own warnings were
/// reported by the first evaluation.
/// </summary>
internal static class RevocationStep
{
    internal static async Task<(ValidationFacts Facts, ValidationEvaluation Evaluation, List<string> Warnings)> RunAsync(
        ValidationFacts facts,
        IReadOnlyList<X509Certificate2> chainCandidates,
        byte[]? signatureTimestampToken,
        IChainRevocationChecker checker,
        IReadOnlyList<byte[]> embeddedCrls,
        IReadOnlyList<byte[]> embeddedOcsps,
        ValidationPolicy policy,
        CancellationToken cancellationToken)
    {
        var warnings = new List<string>();

        if (signatureTimestampToken is not null && facts.IsTsaTrusted == true)
        {
            var tsa = await TimestampTsaChecks.CheckTsaRevocationAsync(
                new TimestampTokenValidationResult { IsIntegrityValid = true, IsTsaTrusted = true, GenTime = TimestampValidator.ReadGenTime(signatureTimestampToken) },
                signatureTimestampToken, chainCandidates, checker, embeddedCrls, embeddedOcsps, allowOnline: true, warnings, cancellationToken)
                .ConfigureAwait(false);
            if (tsa.IsTsaTrusted != true)
            {
                facts = facts with { IsTsaTrusted = false, ProofOfExistence = null };
            }
        }

        if (facts.SignerCertificate is { } signer)
        {
            var ordered = SignerAcceptance.OrderChain(signer, chainCandidates);
            var last = ordered[^1];
            if (!last.SubjectName.RawData.AsSpan().SequenceEqual(last.IssuerName.RawData))
            {
                warnings.Add($"Revocation: the issuer of '{last.Subject}' is unknown, so the revocation of the chain cannot be established.");
                facts = facts with { IsNotRevoked = false, RevocationSource = RevocationSource.Indeterminate };
            }
            else
            {
                var result = await checker.CheckAsync(
                    ordered, facts.ProofOfExistence ?? DateTimeOffset.UtcNow, embeddedCrls, embeddedOcsps, allowOnline: true, cancellationToken)
                    .ConfigureAwait(false);
                warnings.AddRange(result.Messages.Select(m => "Revocation: " + m));
                facts = facts with
                {
                    IsNotRevoked = result.Status == ChainRevocationStatus.Good,
                    RevocationSource = result.Status switch
                    {
                        ChainRevocationStatus.Good or ChainRevocationStatus.Revoked => RevocationSource.CertificateChain,
                        _ => RevocationSource.Indeterminate,
                    },
                };
            }
        }

        var evaluation = ValidationPolicyEvaluator.Evaluate(facts, policy);
        return (facts, evaluation, warnings);
    }
}
