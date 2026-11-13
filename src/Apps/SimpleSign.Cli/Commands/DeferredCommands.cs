using System.ComponentModel;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using SimpleSign.CAdES;
using SimpleSign.Cli.Rendering;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES;
using SimpleSign.XAdES;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

/// <summary>
/// The session integrity key both deferred commands take: hex or base64, at least 32 bytes, or <c>env:NAME</c>.
/// </summary>
internal static class DeferredSessionKey
{
    internal const string Description = "HMAC key that protects the session file, at least 32 bytes as hex or base64 (accepts env:NAME); the same key completes it";

    /// <summary>The key bytes, or null when the value is neither hex nor base64 of at least 32 bytes.</summary>
    internal static byte[]? Parse(string? value)
    {
        string? text = value is null ? null : ExternalCredentialSupport.Secret(value);
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        byte[]? key = SignCommandOptions.ParseHex(text);
        if (key is null)
        {
            try
            {
                key = Convert.FromBase64String(text);
            }
            catch (FormatException)
            {
                return null;
            }
        }

        return key.Length >= 32 ? key : null;
    }

    /// <summary>The error for a missing or short key, or null.</summary>
    internal static string? Validate(string? value)
    {
        if (value is null)
        {
            return "--session-key is required: generate one with, e.g., openssl rand -hex 32.";
        }

        try
        {
            return Parse(value) is null ? "--session-key must be at least 32 bytes, as hex or base64." : null;
        }
        catch (InvalidOperationException ex)
        {
            return ex.Message;
        }
    }
}

/// <summary>
/// Deferred signing, step 1: prepares the PDF for a signer that is elsewhere (a browser, a token, a
/// remote service) and writes the session and the data to sign. <c>deferred complete</c> embeds the signature.
/// </summary>
[Description("Prepare a PDF for a signature made elsewhere: writes the session and the data to sign")]
internal sealed class DeferredPrepareCommand(ICertificateChainService certChainService) : AsyncCommand<DeferredPrepareCommand.Settings>
{
    /// <summary>Settings of <c>deferred prepare</c>.</summary>
    internal sealed class Settings : TimestampedSigningSettings
    {
        /// <summary>Checks run before signing.</summary>
        [CommandOption("--signing-policy <PATH>")]
        [Description(SigningPolicyOption.Description)]
        public string? SigningPolicy { get; init; }

        /// <summary>PDF to prepare.</summary>
        [CommandArgument(0, "<input>")]
        [Description("PDF to prepare")]
        public string InputPath { get; init; } = null!;

        /// <summary>The signer's certificate (public, DER or PEM); further certificates in the file are its chain.</summary>
        [CommandOption("--cert|-c <PATH>")]
        [Description("The signer's certificate, DER or PEM (no private key needed); more certificates in the file are its chain")]
        public string CertPath { get; init; } = null!;

        /// <summary>More chain certificates (PEM or DER).</summary>
        [CommandOption("--chain <PATH>")]
        [Description("More certificates of the signer's chain (PEM or DER)")]
        public string? ChainPath { get; init; }

        /// <summary>HMAC key of the session.</summary>
        [CommandOption("--session-key <KEY>")]
        [Description(DeferredSessionKey.Description)]
        public string? SessionKey { get; init; }

        /// <summary>Where the session goes (default: input.session).</summary>
        [CommandOption("--session <PATH>")]
        [Description("Where the session goes (default: <input>.session)")]
        public string? SessionPath { get; init; }

        /// <summary>Where the data to sign goes (default: input.tbs).</summary>
        [CommandOption("--to-sign <PATH>")]
        [Description("Where the data to sign goes (default: <input>.tbs): the DER signed attributes, which the signer hashes with --hash and signs")]
        public string? ToSignPath { get; init; }

        /// <summary>TSA URL (B-T or higher).</summary>
        [CommandOption("--tsa|-t <URL>")]
        [Description("TSA URL for the signature timestamp, added by 'deferred complete'")]
        public string? TsaUrl { get; init; }

        /// <summary>B-LT.</summary>
        [CommandOption("--ltv")]
        [Description("PAdES B-LT: embed the revocation data (requires --tsa)")]
        public bool Ltv { get; init; }

        /// <summary>B-LTA.</summary>
        [CommandOption("--archival")]
        [Description("PAdES B-LTA: B-LT plus a document timestamp (requires --tsa)")]
        public bool Archival { get; init; }

        /// <summary>A separate archive TSA.</summary>
        [CommandOption("--archive-tsa <URL>")]
        [Description("A separate TSA for the archive timestamp. Requires --archival.")]
        public string? ArchiveTsaUrl { get; init; }

        /// <summary>Return the highest level reached instead of failing.</summary>
        [CommandOption("--return-lower-level")]
        [Description("Return the highest level reached instead of failing when a timestamp or revocation data is missing")]
        public bool ReturnLowerLevel { get; init; }

        /// <summary>Revocation source tried first: ocsp or crl.</summary>
        [CommandOption("--revocation-preference <SOURCE>")]
        [Description("Revocation source tried first for B-LT and B-LTA: ocsp (default) or crl")]
        public string? RevocationPreference { get; init; }

        /// <summary>Hash algorithm.</summary>
        [CommandOption("--hash <ALGORITHM>")]
        [Description("Hash algorithm: SHA256 (default), SHA384, SHA512, SHA3-256, SHA3-384 or SHA3-512")]
        public string? Hash { get; init; }

        /// <summary>RSA scheme.</summary>
        [CommandOption("--signature-algorithm <ALGO>")]
        [Description("RSA signature scheme: rsa-pkcs1 (default) or rsassa-pss")]
        public string? SignatureAlgorithm { get; init; }

        /// <summary>Signature field name.</summary>
        [CommandOption("--field-name <NAME>")]
        [Description("Name of the new signature field (default Signature1)")]
        public string? FieldName { get; init; }

        /// <summary>Declared signer name.</summary>
        [CommandOption("--signer-name <NAME>")]
        [Description("Signer name in the signature dictionary")]
        public string? SignerName { get; init; }

        /// <summary>Reason.</summary>
        [CommandOption("--reason <TEXT>")]
        [Description("Reason for signing")]
        public string? Reason { get; init; }

        /// <summary>Location.</summary>
        [CommandOption("--location <TEXT>")]
        [Description("Signing location")]
        public string? Location { get; init; }

        /// <summary>Contact information.</summary>
        [CommandOption("--contact <TEXT>")]
        [Description("Signer contact information")]
        public string? Contact { get; init; }

        /// <summary>Bytes reserved for the CMS.</summary>
        [CommandOption("--contents-size <BYTES>")]
        [Description("Bytes reserved for the signature in /Contents (default 16384)")]
        public int? ContentsSize { get; init; }

        /// <summary>Print the result as JSON.</summary>
        [CommandOption("--json")]
        [Description("Print the session and data-to-sign paths and the algorithms as JSON")]
        public bool Json { get; init; }

        internal PadesProfileOptions.Level LevelOptions => new(TsaUrl, Ltv, Archival, ArchiveTsaUrl, ReturnLowerLevel, RevocationPreference);

        public override ValidationResult Validate()
        {
            if (!File.Exists(InputPath))
            {
                return ValidationResult.Error($"File not found: {InputPath}");
            }

            if (CertPath is null || !File.Exists(CertPath))
            {
                return ValidationResult.Error(CertPath is null ? "--cert is required: the signer's public certificate." : $"Certificate not found: {CertPath}");
            }

            if (ChainPath is not null && !File.Exists(ChainPath))
            {
                return ValidationResult.Error($"Chain not found: {ChainPath}");
            }

            string? error = DeferredSessionKey.Validate(SessionKey)
                ?? PadesProfileOptions.Validate(LevelOptions)
                ?? PadesProfileOptions.ValidateCrypto(Hash, SignatureAlgorithm, ContentsSize)
                ?? ValidateTsaCredentials(TsaUrl)
                ?? (SigningPolicyOption.IsValid(SigningPolicy) ? null : SigningPolicyOption.Error(SigningPolicy));
            return error is null ? ValidationResult.Success() : ValidationResult.Error(error);
        }
    }

    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        byte[] pdf = await File.ReadAllBytesAsync(settings.InputPath, cancellationToken);
        List<X509Certificate2> certificates = [.. certChainService.LoadCertsFromBytes(await File.ReadAllBytesAsync(settings.CertPath, cancellationToken))];
        if (settings.ChainPath is not null)
        {
            certificates.AddRange(certChainService.LoadCertsFromBytes(await File.ReadAllBytesAsync(settings.ChainPath, cancellationToken)));
        }

        try
        {
            var builder = DeferredSigner.Document(pdf)
                .WithCertificate(certificates[0], certificates[1..])
                .WithSessionIntegrityKey(DeferredSessionKey.Parse(settings.SessionKey)!)
                .WithHashAlgorithm(SignCommandOptions.ParseHash(settings.Hash ?? "SHA256"))
                .WithFieldOptions(PadesProfileOptions.Field(
                    settings.FieldName, settings.SignerName, settings.Reason, settings.Location, settings.Contact, settings.ContentsSize))
                .WithLevel(PadesProfileOptions.Build(settings.LevelOptions, settings));
            if (settings.SignatureAlgorithm is not null && SignCommandOptions.ParseSignatureAlgorithm(settings.SignatureAlgorithm) is { } oid)
            {
                builder = builder.WithSignatureAlgorithm(oid);
            }

            builder = builder.WithSigningPolicy(await settings.SigningPolicyAsync(settings.SigningPolicy, cancellationToken)).WithTrustAnchors(await settings.SigningTrustAnchorsAsync(cancellationToken));
            if (settings.AuditSink() is { } audit)
            {
                builder = builder.WithAuditSink(audit);
            }
            if (CliNetwork.IsConfigured)
            {
                builder = builder.WithHttpClientProvider(CliNetwork.Provider);
            }

            var prepared = await builder.PrepareAsync(cancellationToken);
            string sessionPath = settings.SessionPath ?? settings.InputPath + ".session";
            string toSignPath = settings.ToSignPath ?? settings.InputPath + ".tbs";
            await File.WriteAllBytesAsync(sessionPath, prepared.SessionData, cancellationToken);
            await File.WriteAllBytesAsync(toSignPath, prepared.HashToSign, cancellationToken);

            DeferredPrepareSupport.Report(
                settings.InputPath, "pades", sessionPath, toSignPath, prepared.HashToSign.Length,
                prepared.DigestAlgorithm, prepared.SignatureAlgorithmOid, settings.Json);
            return 0;
        }
        finally
        {
            foreach (var certificate in certificates)
            {
                certificate.Dispose();
            }
        }
    }
}

/// <summary>
/// Deferred signing, step 2: completes with the signature made elsewhere a session written by
/// <c>deferred prepare</c> or by <c>sign</c>, <c>cades sign</c> or <c>xades sign</c> with <c>--prepare</c>.
/// The format (PAdES, CAdES or XAdES) is read from the session.
/// </summary>
[Description("Complete a prepared signature (PAdES, CAdES or XAdES) with the signature made elsewhere")]
internal sealed class DeferredCompleteCommand : AsyncCommand<DeferredCompleteCommand.Settings>
{
    /// <summary>Settings of <c>deferred complete</c>.</summary>
    internal sealed class Settings : TimestampedSigningSettings
    {
        /// <summary>Checks run before signing.</summary>
        [CommandOption("--signing-policy <PATH>")]
        [Description(SigningPolicyOption.Description)]
        public string? SigningPolicy { get; init; }

        /// <summary>The session written by deferred prepare.</summary>
        [CommandArgument(0, "<session>")]
        [Description("The session written by 'deferred prepare'")]
        public string SessionPath { get; init; } = null!;

        /// <summary>HMAC key of the session.</summary>
        [CommandOption("--session-key <KEY>")]
        [Description(DeferredSessionKey.Description)]
        public string? SessionKey { get; init; }

        /// <summary>The raw signature of the data to sign.</summary>
        [CommandOption("--signature <PATH>")]
        [Description("The raw signature of the data to sign (RSA, or ECDSA in DER)")]
        public string SignaturePath { get; init; } = null!;

        /// <summary>The signed PDF, CMS or XML.</summary>
        [CommandOption("--output|-o <PATH>")]
        [Description("The signed PDF, CMS (.p7s/.p7m) or XML")]
        public string OutputPath { get; init; } = null!;

        /// <summary>The content of a CAdES session prepared with --content-outside-session.</summary>
        [CommandOption("--content <PATH>")]
        [Description("CAdES: the signed content, for a session prepared with --content-outside-session")]
        public string? ContentPath { get; init; }

        /// <summary>The detached document of a XAdES session prepared with --detached-data-outside-session.</summary>
        [CommandOption("--detached-data <PATH>")]
        [Description("XAdES: the detached document, for a session prepared with --detached-data-outside-session")]
        public string? DetachedDataPath { get; init; }

        /// <summary>The external data objects of a XAdES session prepared with --detached-data-outside-session.</summary>
        [CommandOption("--external-object <URI=PATH>")]
        [Description("XAdES: an external data object by the URI of its reference, for a session prepared with --detached-data-outside-session (repeat for more)")]
        public string[]? ExternalObjects { get; init; }

        /// <summary>Print the result as JSON.</summary>
        [CommandOption("--json")]
        [Description("Print the result as JSON")]
        public bool Json { get; init; }

        /// <summary>The TSA again, only when it needs credentials (they are not kept in the session).</summary>
        [CommandOption("--tsa|-t <URL>")]
        [Description("The TSA of 'deferred prepare', only with --tsa-user, --tsa-token or --tsa-cert: credentials are never stored in the session")]
        public string? TsaUrl { get; init; }

        /// <summary>The archive TSA again, with the credentials.</summary>
        [CommandOption("--archive-tsa <URL>")]
        [Description("The archive TSA of 'deferred prepare', with the TSA credentials")]
        public string? ArchiveTsaUrl { get; init; }

        public override ValidationResult Validate()
        {
            if (!File.Exists(SessionPath))
            {
                return ValidationResult.Error($"Session not found: {SessionPath}");
            }

            if (SignaturePath is null || !File.Exists(SignaturePath))
            {
                return ValidationResult.Error(SignaturePath is null ? "--signature is required." : $"Signature not found: {SignaturePath}");
            }

            if (OutputPath is null)
            {
                return ValidationResult.Error("--output is required.");
            }

            foreach (string path in new[] { ContentPath, DetachedDataPath }.OfType<string>())
            {
                if (!File.Exists(path))
                {
                    return ValidationResult.Error($"File not found: {path}");
                }
            }

            foreach (string entry in ExternalObjects ?? [])
            {
                int separator = entry.IndexOf('=', StringComparison.Ordinal);
                if (separator <= 0 || !File.Exists(entry[(separator + 1)..]))
                {
                    return ValidationResult.Error($"--external-object takes URI=PATH with an existing file: {entry}");
                }
            }

            if ((TsaUrl is not null || ArchiveTsaUrl is not null) && !HasTsaCredentials)
            {
                return ValidationResult.Error("--tsa and --archive-tsa are only needed with TSA credentials: the session keeps the TSA URL.");
            }

            string? error = DeferredSessionKey.Validate(SessionKey) ?? ValidateTsaCredentials(TsaUrl)
                ?? (SigningPolicyOption.IsValid(SigningPolicy) ? null : SigningPolicyOption.Error(SigningPolicy));
            return error is null ? ValidationResult.Success() : ValidationResult.Error(error);
        }
    }

    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        SignJson.Enabled = settings.Json;
        byte[] session = await File.ReadAllBytesAsync(settings.SessionPath, cancellationToken);
        byte[] signature = await File.ReadAllBytesAsync(settings.SignaturePath, cancellationToken);
        byte[] key = DeferredSessionKey.Parse(settings.SessionKey)!;
        var policy = await settings.SigningPolicyAsync(settings.SigningPolicy, cancellationToken);
        var anchors = await settings.SigningTrustAnchorsAsync(cancellationToken);
        var audit = settings.AuditSink();
        TimestampOptions? timestamp = settings.TsaUrl is null ? null : settings.Timestamp(settings.TsaUrl);
        ArchiveTimestampOptions? archiveTimestamp = settings.ArchiveTsaUrl is null ? null : settings.ArchiveTimestamp(settings.ArchiveTsaUrl);

        string format = SessionFormat(session);
        string? misplaced = format switch
        {
            "cades" => settings.DetachedDataPath is not null || settings.ExternalObjects is { Length: > 0 } ? "--detached-data and --external-object are for a XAdES session; this one is CAdES." : null,
            "xades" => settings.ContentPath is not null ? "--content is for a CAdES session; this one is XAdES." : null,
            _ => settings.ContentPath is not null || settings.DetachedDataPath is not null || settings.ExternalObjects is { Length: > 0 }
                ? "--content, --detached-data and --external-object are for CAdES and XAdES sessions; this one is PAdES." : null,
        };
        if (misplaced is not null)
        {
            throw new InvalidOperationException(misplaced);
        }

        ISigningResult result;
        byte[] signed;
        switch (format)
        {
            case "cades":
                {
                    var builder = CadesDeferredSigner.Resume(session, key).WithSigningPolicy(policy).WithTrustAnchors(anchors);
                    builder = timestamp is null ? builder : builder.WithTimestampOptions(timestamp, archiveTimestamp);
                    builder = audit is null ? builder : builder.WithAuditSink(audit);
                    builder = CliNetwork.IsConfigured ? builder.WithHttpClientProvider(CliNetwork.Provider) : builder;
                    if (settings.ContentPath is not null)
                    {
                        builder = builder.WithContent(await File.ReadAllBytesAsync(settings.ContentPath, cancellationToken));
                    }

                    var details = await builder.CompleteWithDetailsAsync(signature, cancellationToken);
                    (result, signed) = (details, details.SignedArtifact);
                    break;
                }

            case "xades":
                {
                    var builder = XadesDeferredSigner.Resume(session, key).WithSigningPolicy(policy).WithTrustAnchors(anchors);
                    builder = timestamp is null ? builder : builder.WithTimestampOptions(timestamp, archiveTimestamp);
                    builder = audit is null ? builder : builder.WithAuditSink(audit);
                    builder = CliNetwork.IsConfigured ? builder.WithHttpClientProvider(CliNetwork.Provider) : builder;
                    if (settings.DetachedDataPath is not null)
                    {
                        builder = builder.WithDetachedData(await File.ReadAllBytesAsync(settings.DetachedDataPath, cancellationToken));
                    }

                    foreach (string entry in settings.ExternalObjects ?? [])
                    {
                        int separator = entry.IndexOf('=', StringComparison.Ordinal);
                        builder = builder.WithExternalData(entry[..separator], await File.ReadAllBytesAsync(entry[(separator + 1)..], cancellationToken));
                    }

                    var details = await builder.CompleteWithDetailsAsync(signature, cancellationToken);
                    (result, signed) = (details, details.SignedArtifact);
                    break;
                }

            default:
                {
                    var builder = DeferredSigner.Resume(session, key).WithSigningPolicy(policy).WithTrustAnchors(anchors);
                    builder = timestamp is null ? builder : builder.WithTimestampOptions(timestamp, archiveTimestamp);
                    builder = audit is null ? builder : builder.WithAuditSink(audit);
                    builder = CliNetwork.IsConfigured ? builder.WithHttpClientProvider(CliNetwork.Provider) : builder;
                    var details = await builder.CompleteWithDetailsAsync(signature, cancellationToken);
                    (result, signed) = (details, details.SignedArtifact);
                    break;
                }
        }

        await File.WriteAllBytesAsync(settings.OutputPath, signed, cancellationToken);
        if (settings.Json)
        {
            SignJson.WriteSuccess(format, settings.OutputPath, signer: string.Empty, result);
            return 0;
        }

        AnsiConsole.MarkupLine($"[green]✓ Signed:[/] {settings.OutputPath.EscapeMarkup()} ({SignJson.Level(result.AchievedLevel)})");
        foreach (var warning in result.Warnings)
        {
            AnsiConsole.MarkupLine($"  [yellow]![/] {warning.Message.EscapeMarkup()}");
        }

        return 0;
    }

    /// <summary>
    /// The format of a session: CAdES and XAdES sessions name theirs in the envelope; a PAdES session is the
    /// session object itself.
    /// </summary>
    internal static string SessionFormat(byte[] session)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(session);
            return document.RootElement.ValueKind == JsonValueKind.Object
                && document.RootElement.TryGetProperty("format", out JsonElement format)
                && format.ValueKind == JsonValueKind.String
                ? format.GetString()!.ToLowerInvariant()
                : "pades";
        }
        catch (JsonException)
        {
            return "pades";
        }
    }
}
