using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Cli.Json;
using SimpleSign.Core.Validation;
using Spectre.Console;

namespace SimpleSign.Cli.Rendering;

/// <summary>
/// The verification report shared by the validate commands (INDECOPI Req. 18/28): the indication and its reason,
/// the public key of the signer, and every check of the validation, in English or Spanish.
/// </summary>
internal static class ValidationReportRenderer
{
    /// <summary>Adds the report under <paramref name="parent"/>.</summary>
    internal static void AddNodes(
        TreeNode parent, SignatureIndication indication, SignatureSubIndication? subIndication,
        IReadOnlyList<ValidationConstraintResult> constraints, X509Certificate2? signer, bool spanish)
    {
        var report = parent.AddNode($"[blue]{(spanish ? "Informe de verificación" : "Verification report")}[/]");
        foreach (string line in Lines(indication, subIndication, constraints, signer, spanish))
        {
            report.AddNode(line);
        }
    }

    /// <summary>Writes the report to the console.</summary>
    internal static void Write(
        SignatureIndication indication, SignatureSubIndication? subIndication,
        IReadOnlyList<ValidationConstraintResult> constraints, X509Certificate2? signer, bool spanish)
    {
        AnsiConsole.MarkupLine($"\n[blue]{(spanish ? "Informe de verificación" : "Verification report")}[/]");
        foreach (string line in Lines(indication, subIndication, constraints, signer, spanish))
        {
            AnsiConsole.MarkupLine("  " + line);
        }
    }

    private static IEnumerable<string> Lines(
        SignatureIndication indication, SignatureSubIndication? subIndication,
        IReadOnlyList<ValidationConstraintResult> constraints, X509Certificate2? signer, bool spanish)
    {
        string color = indication switch
        {
            SignatureIndication.Valid => "green",
            SignatureIndication.Invalid => "red",
            _ => "yellow",
        };
        yield return $"{(spanish ? "Resultado" : "Indication")}:    [{color}]{IndicationName(indication, spanish)}[/]"
            + (subIndication is { } sub ? $" ({EtsiName(sub)})" : string.Empty);

        if (signer is not null)
        {
            var key = PublicKey(signer);
            yield return $"{(spanish ? "Clave pública" : "Public key")}: {key.Algorithm} {key.Size} bits";
            yield return $"SPKI SHA-256:  {key.Sha256}";
            foreach (string pemLine in key.Pem.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                yield return $"[dim]{pemLine.EscapeMarkup()}[/]";
            }
        }

        foreach (var constraint in constraints)
        {
            string mark = constraint.Status switch
            {
                ConstraintStatus.Passed => "[green]✓[/]",
                ConstraintStatus.Warning => "[yellow]![/]",
                ConstraintStatus.Failed => "[red]✗[/]",
                ConstraintStatus.Indeterminate => "[yellow]?[/]",
                _ => "[dim]–[/]",
            };
            yield return $"{mark} {constraint.Id.EscapeMarkup()}: {constraint.Message.EscapeMarkup()}";
        }
    }

    /// <summary>The JSON view of the report.</summary>
    internal static (string? SubIndication, List<ConstraintDto> Constraints, PublicKeyDto? PublicKey) ToDto(
        SignatureSubIndication? subIndication, IReadOnlyList<ValidationConstraintResult> constraints, X509Certificate2? signer)
    {
        (string Algorithm, int Size, string Sha256, string Pem)? key = signer is null ? null : PublicKey(signer);
        return (
            subIndication is { } sub ? EtsiName(sub) : null,
            [.. constraints.Select(c => new ConstraintDto
            {
                Id = c.Id,
                Status = c.Status.ToString(),
                SubIndication = c.SubIndication is { } s ? EtsiName(s) : null,
                Message = c.Message,
            })],
            key is { } k ? new PublicKeyDto { Algorithm = k.Algorithm, SizeBits = k.Size, SpkiSha256 = k.Sha256, Pem = k.Pem } : null);
    }

    /// <summary>The ETSI EN 319 102-1 name of a sub-indication (HASH_FAILURE…).</summary>
    internal static string EtsiName(SignatureSubIndication subIndication) => subIndication switch
    {
        SignatureSubIndication.FormatFailure => "FORMAT_FAILURE",
        SignatureSubIndication.HashFailure => "HASH_FAILURE",
        SignatureSubIndication.SigCryptoFailure => "SIG_CRYPTO_FAILURE",
        SignatureSubIndication.Revoked => "REVOKED",
        SignatureSubIndication.NotYetValid => "NOT_YET_VALID",
        SignatureSubIndication.SigConstraintsFailure => "SIG_CONSTRAINTS_FAILURE",
        SignatureSubIndication.ChainConstraintsFailure => "CHAIN_CONSTRAINTS_FAILURE",
        SignatureSubIndication.CryptoConstraintsFailure => "CRYPTO_CONSTRAINTS_FAILURE",
        SignatureSubIndication.CryptoConstraintsFailureNoPoe => "CRYPTO_CONSTRAINTS_FAILURE_NO_POE",
        SignatureSubIndication.NoSigningCertificateFound => "NO_SIGNING_CERTIFICATE_FOUND",
        SignatureSubIndication.NoCertificateChainFound => "NO_CERTIFICATE_CHAIN_FOUND",
        SignatureSubIndication.OutOfBoundsNoPoe => "OUT_OF_BOUNDS_NO_POE",
        SignatureSubIndication.RevokedNoPoe => "REVOKED_NO_POE",
        SignatureSubIndication.TryLater => "TRY_LATER",
        SignatureSubIndication.TimestampOrderFailure => "TIMESTAMP_ORDER_FAILURE",
        _ => subIndication.ToString(),
    };

    private static string IndicationName(SignatureIndication indication, bool spanish) => (indication, spanish) switch
    {
        (SignatureIndication.Valid, false) => "TOTAL-PASSED (valid)",
        (SignatureIndication.Invalid, false) => "TOTAL-FAILED (invalid)",
        (_, false) => "INDETERMINATE",
        (SignatureIndication.Valid, true) => "FIRMA VÁLIDA (TOTAL-PASSED)",
        (SignatureIndication.Invalid, true) => "FIRMA INVÁLIDA (TOTAL-FAILED)",
        _ => "INDETERMINADA (INDETERMINATE)",
    };

    private static (string Algorithm, int Size, string Sha256, string Pem) PublicKey(X509Certificate2 certificate)
    {
        byte[] spki = certificate.PublicKey.ExportSubjectPublicKeyInfo();
        string algorithm = certificate.PublicKey.Oid.FriendlyName ?? certificate.PublicKey.Oid.Value ?? "?";
        int size;
        using (var rsa = certificate.GetRSAPublicKey())
        using (var ecdsa = rsa is null ? certificate.GetECDsaPublicKey() : null)
        {
            size = rsa?.KeySize ?? ecdsa?.KeySize ?? 0;
        }

        return (algorithm, size, Convert.ToHexString(SHA256.HashData(spki)),
            PemEncoding.WriteString("PUBLIC KEY", spki));
    }
}
