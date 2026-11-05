using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Brasil;
using SimpleSign.Brasil.IcpBrasil;
using SimpleSign.Brasil.Signing;
using SimpleSign.Brasil.Xades;
using SimpleSign.CAdES;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Validation;
using SimpleSign.XAdES;

namespace SimpleSign.Desktop.Services;

internal enum SignatureFormat
{
    Pades,
    CadesDetached,
    CadesAttached,
    Xades,
}

internal enum SignatureLevel
{
    Basic,
    Timestamped,
    LongTerm,
    Archive,
}

internal sealed record SignRequest(
    byte[] Input,
    string FileName,
    SignatureFormat Format,
    SignatureLevel Level,
    IcpBrasilPolicy? IcpPolicy,
    string? TsaUrl,
    string? Reason = null,
    string? Location = null,
    bool VisibleStamp = false);

internal enum CheckState
{
    Ok,
    Warning,
    Failed,
    NotApplicable,
}

internal sealed record CheckItem(string Label, CheckState State, string? Detail = null);

internal sealed record DetailItem(string Key, string Value);

/// <summary>One signature (or timestamp) of a validated document, ready to show.</summary>
internal sealed record SignatureReport(
    string Title,
    CheckState Verdict,
    string VerdictText,
    string? Signer,
    string? SigningTime,
    IReadOnlyList<CheckItem> Checks,
    IReadOnlyList<DetailItem> Details,
    IReadOnlyList<string> Errors,
    IReadOnlyList<string> Warnings);

/// <summary>Signs and validates documents with the library.</summary>
internal sealed class DocumentService(SettingsStore settings)
{
    public static IReadOnlyList<IcpBrasilPolicy> PoliciesFor(SignatureFormat format) => format == SignatureFormat.Pades
        ? [IcpBrasilPolicy.AdRb, IcpBrasilPolicy.AdRt]
        : [IcpBrasilPolicy.AdRb, IcpBrasilPolicy.AdRt, IcpBrasilPolicy.AdRv, IcpBrasilPolicy.AdRc, IcpBrasilPolicy.AdRa];

    public static SignatureFormat DefaultFormatFor(string fileName) => Path.GetExtension(fileName).ToUpperInvariant() switch
    {
        ".PDF" => SignatureFormat.Pades,
        ".XML" => SignatureFormat.Xades,
        _ => SignatureFormat.CadesDetached,
    };

    public static string OutputName(string fileName, SignatureFormat format)
    {
        string name = Path.GetFileNameWithoutExtension(fileName);
        string extension = Path.GetExtension(fileName);
        return format switch
        {
            SignatureFormat.CadesDetached => fileName + ".p7s",
            SignatureFormat.CadesAttached => fileName + ".p7m",
            _ => $"{name}-assinado{extension}",
        };
    }

    public async Task<byte[]> SignAsync(SignRequest request, SigningCredential credential, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(credential);
        var tsa = string.IsNullOrWhiteSpace(request.TsaUrl) ? null : new TimestampOptions(new Uri(request.TsaUrl));
        if ((request.Level != SignatureLevel.Basic || request.IcpPolicy is { } p && p != IcpBrasilPolicy.AdRb) && tsa is null)
        {
            throw new InvalidOperationException("Este nível precisa de um servidor de carimbo do tempo (TSA/ACT). Configure-o em Ajustes.");
        }

        var profile = Profile(request.Level, tsa);
        switch (request.Format)
        {
            case SignatureFormat.Pades:
                {
                    var builder = PadesSigner.Document(request.Input);
                    builder = credential.External is { } external
                        ? builder.WithExternalSigner(credential.Certificate, external, credential.Chain)
                        : builder.WithCertificate(credential.Certificate, credential.Chain);
                    builder = request.IcpPolicy is { } icp ? builder.WithIcpBrasilPolicy(icp, tsa) : builder.WithLevel(profile);
                    if (!string.IsNullOrWhiteSpace(request.Reason) || !string.IsNullOrWhiteSpace(request.Location))
                    {
                        builder = builder.WithFieldOptions(new SignatureFieldOptions { Reason = request.Reason, Location = request.Location });
                    }

                    if (request.VisibleStamp)
                    {
                        builder = builder.WithAppearance(new SignatureAppearance
                        {
                            AutoPosition = true,
                            ShowReason = !string.IsNullOrWhiteSpace(request.Reason),
                            ShowLocation = !string.IsNullOrWhiteSpace(request.Location),
                        }.WithLabels("Assinado digitalmente por", "Motivo", "Local", "Data"));
                    }

                    return await builder.SignAsync(cancellationToken);
                }

            case SignatureFormat.CadesDetached or SignatureFormat.CadesAttached:
                {
                    var builder = CadesSigner.Document(request.Input)
                        .WithContentType(request.Format == SignatureFormat.CadesAttached ? CadesContentType.Enveloped : CadesContentType.Detached);
                    builder = credential.External is { } external
                        ? builder.WithExternalSigner(credential.Certificate, external, credential.Chain)
                        : builder.WithCertificate(credential.Certificate, credential.Chain);
                    builder = request.IcpPolicy is { } icp ? builder.WithIcpBrasilPolicy(icp, tsa) : builder.WithLevel(profile);
                    return await builder.SignAsync(cancellationToken);
                }

            default:
                {
                    var builder = XadesSigner.Document(request.Input);
                    builder = credential.External is { } external
                        ? builder.WithExternalSigner(credential.Certificate, external, credential.Chain)
                        : builder.WithCertificate(credential.Certificate, credential.Chain);
                    builder = request.IcpPolicy is { } icp ? builder.WithIcpBrasilPolicy(icp, tsa) : builder.WithLevel(profile);
                    return await builder.SignAsync(cancellationToken);
                }
        }
    }

    /// <summary>Validates a PDF, a CAdES signature (.p7s with its data, or .p7m) or a signed XML.</summary>
    public async Task<IReadOnlyList<SignatureReport>> ValidateAsync(string fileName, byte[] content, byte[]? detachedData, CancellationToken cancellationToken)
    {
        string extension = Path.GetExtension(fileName).ToUpperInvariant();
        return extension switch
        {
            ".PDF" => await ValidatePdfAsync(content, cancellationToken),
            ".XML" => ValidateXml(content),
            _ => ValidateCades(content, detachedData),
        };
    }

    private IcpBrasilEnvironment Environment => settings.Current.IcpHomologation ? IcpBrasilEnvironment.Homologation : IcpBrasilEnvironment.Production;

    private IReadOnlyList<X509Certificate2> IcpRoots => Environment == IcpBrasilEnvironment.Homologation
        ? [.. IcpBrasilChainValidator.LoadBundledAcRaizCerts(), .. IcpBrasilChainValidator.LoadBundledHomologationRoots()]
        : IcpBrasilChainValidator.LoadBundledAcRaizCerts();

    private async Task<IReadOnlyList<SignatureReport>> ValidatePdfAsync(byte[] pdf, CancellationToken cancellationToken)
    {
        var brasil = new BrasilExtension(new BrasilExtensionOptions
        {
            IcpEnvironment = Environment,
            CrlCacheDirectory = string.IsNullOrWhiteSpace(settings.Current.CrlCacheDirectory) ? null : settings.Current.CrlCacheDirectory,
        });
        var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = true }, null, null,
            brasil.TrustAnchorProviders, brasil.ChainValidationProviders);
        using var stream = new MemoryStream(pdf);
        var results = await validator.ValidateAsync(stream, cancellationToken: cancellationToken);
        var levels = new Dictionary<string, PAdESConformanceLevel>(StringComparer.Ordinal);
        try
        {
            stream.Position = 0;
            var inspection = await PdfSignatureInspector.InspectAsync(stream, cancellationToken: cancellationToken);
            foreach (var (signature, level) in ConformanceDetector.DetectAll(inspection))
            {
                levels[signature.FieldName] = level;
            }
        }
        catch (InvalidDataException)
        {
            // Levels are best-effort.
        }

        return [.. results.Select(r => FromPdf(r, levels.TryGetValue(r.FieldName, out var l) ? l : null))];
    }

    private static SignatureReport FromPdf(SignatureValidationResult r, PAdESConformanceLevel? level)
    {
        var checks = new List<CheckItem>
        {
            new("Integridade do documento", r.IsIntegrityValid ? CheckState.Ok : CheckState.Failed),
            new("Assinatura criptográfica", r.IsSignatureValid ? CheckState.Ok : CheckState.Failed),
            new("Cadeia de certificação", r.IsCertificateChainValid ? CheckState.Ok : r.IsChainTrustWarning ? CheckState.Warning : CheckState.Failed,
                r.ChainValidationRegion is { } region ? $"Validada pelo provedor {region}" : null),
            new("Revogação", r.IsNotRevoked ? CheckState.Ok : CheckState.Warning, r.RevocationSource.ToString()),
            Optional("Carimbo do tempo", r.HasValidTimestamp, r.IsTsaTrusted == false ? "TSA não confiável" : null),
        };
        var details = new List<DetailItem>();
        if (level is { } l)
        {
            details.Add(new("Nível", l.ToString().Replace("Baseline", "PAdES B-", StringComparison.Ordinal)));
        }

        if (r.SubFilter is { } subFilter)
        {
            details.Add(new("SubFilter", subFilter));
        }

        if (r.SignerId is { } id)
        {
            details.Add(new(r.SignerIdType ?? "ID", id));
        }

        foreach (var (key, value) in r.ChainValidationMetadata ?? new Dictionary<string, string>())
        {
            details.Add(new(Pretty(key), value));
        }

        return new SignatureReport(
            r.IsDocumentTimestamp ? $"Carimbo do documento · {r.FieldName}" : r.FieldName,
            Verdict(r.Indication), VerdictText(r.Indication), r.SignerName, Time(r.SigningTime), checks, details, r.Errors, r.Warnings);
    }

    private IReadOnlyList<SignatureReport> ValidateCades(byte[] cms, byte[]? data)
    {
        var validator = new CadesSignatureValidator(new ValidationOptions { CheckRevocation = false, TrustSystemRoots = true });
        var result = validator.Validate(cms, data, IcpRoots);
        var checks = new List<CheckItem>
        {
            new("Conteúdo assinado", result.IsIntegrityValid ? CheckState.Ok : CheckState.Failed),
            new("Assinatura criptográfica", result.IsSignatureValid ? CheckState.Ok : CheckState.Failed),
            new("Cadeia de certificação", result.IsCertificateChainValid ? CheckState.Ok : CheckState.Failed),
            Optional("Carimbo da assinatura", result.HasValidTimestamp),
            Optional("Carimbo sobre as referências (AD-RV/RC)", result.HasValidEscTimestamp),
            Optional("Dados de validação (LTV)", result.IsLtvDataValid),
            Optional("Carimbo de arquivamento (AD-RA)", result.HasValidArchiveTimestamp),
        };
        var details = new List<DetailItem>();
        var errors = new List<string>(result.Errors);
        try
        {
            var parsed = CmsParser.Parse(cms);
            var root = parsed.SignerCertificate is { } signer ? IcpBrasilChainValidator.FindBundledRoot(signer, parsed.Certificates, Environment) : null;
            var policy = IcpBrasilPolicyValidator.Validate(parsed, result.SigningTime ?? DateTimeOffset.UtcNow, IcpBrasilPolicyFormat.Cades, root);
            AddPolicy(policy, checks, details, errors);
        }
        catch (System.Formats.Asn1.AsnContentException)
        {
            // Already reported by the validator.
        }

        bool valid = result.IsIntegrityValid && result.IsSignatureValid && result.IsCertificateChainValid;
        return [new SignatureReport("Assinatura CAdES", valid ? CheckState.Ok : CheckState.Failed, valid ? "Válida" : "Inválida",
            result.SignerCertificate?.GetNameInfo(X509NameType.SimpleName, false), Time(result.SigningTime), checks, details, errors, result.Warnings)];
    }

    private IReadOnlyList<SignatureReport> ValidateXml(byte[] xml)
    {
        var validator = new XadesSignatureValidator(new ValidationOptions { CheckRevocation = false, TrustSystemRoots = true });
        return [.. validator.ValidateAll(xml, IcpRoots).Select((result, index) =>
        {
            var checks = new List<CheckItem>
            {
                new("Integridade e assinatura", result.IsSignatureValid && result.IsIntegrityValid ? CheckState.Ok : CheckState.Failed),
                new("Cadeia de certificação", result.IsCertificateChainValid ? CheckState.Ok : CheckState.Failed),
                Optional("SignatureTimeStamp", result.HasValidSignatureTimeStamp),
                Optional("Referências completas (XAdES-C)", result.HasValidCompleteReferences),
                Optional("SigAndRefsTimeStamp (XAdES-X)", result.HasValidSigAndRefsTimeStamp),
                Optional("Dados LTV", result.IsLtvDataValid),
                Optional("ArchiveTimeStamp", result.HasValidArchiveTimeStamp),
            };
            var details = new List<DetailItem> { new("Nível detectado", result.DetectedLevel.ToString()) };
            var errors = new List<string>(result.Errors);
            if (result.SignaturePolicy is not null)
            {
                AddPolicy(IcpBrasilXadesPolicyValidator.Validate(xml, result, Environment), checks, details, errors);
            }

            return new SignatureReport(result.SignatureId ?? $"Assinatura {index + 1}", result.IsValid ? CheckState.Ok : CheckState.Failed,
                result.IsValid ? "Válida" : "Inválida", result.SignerCertificate?.GetNameInfo(X509NameType.SimpleName, false),
                Time(result.SigningTime), checks, details, errors, result.Warnings);
        })];
    }

    private static void AddPolicy(IcpBrasilPolicyValidationResult policy, List<CheckItem> checks, List<DetailItem> details, List<string> errors)
    {
        if (policy.Status == IcpBrasilPolicyStatus.None)
        {
            return;
        }

        checks.Add(new("Política ICP-Brasil", policy.Status switch
        {
            IcpBrasilPolicyStatus.Valid => CheckState.Ok,
            IcpBrasilPolicyStatus.Invalid => CheckState.Failed,
            _ => CheckState.Warning,
        }, policy.Status.ToString()));
        if (policy.Policy is { } p)
        {
            details.Add(new("Política", $"{p.Info.Format} {p.Info.Policy} v{p.Info.Version} ({p.Oid})"));
        }

        errors.AddRange(policy.Errors.Select(e => $"Política: {e}"));
    }

    private static CheckItem Optional(string label, bool? value, string? detail = null) =>
        new(label, value switch { true => CheckState.Ok, false => CheckState.Failed, null => CheckState.NotApplicable }, value is null ? "não presente" : detail);

    private static CheckState Verdict(SignatureIndication indication) => indication switch
    {
        SignatureIndication.Valid => CheckState.Ok,
        SignatureIndication.Indeterminate => CheckState.Warning,
        _ => CheckState.Failed,
    };

    private static string VerdictText(SignatureIndication indication) => indication switch
    {
        SignatureIndication.Valid => "Válida",
        SignatureIndication.Indeterminate => "Indeterminada",
        _ => "Inválida",
    };

    private static string? Time(DateTimeOffset? time) =>
        time?.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss", CultureInfo.InvariantCulture);

    private static string Pretty(string key) => key switch
    {
        "BR.Hierarchy" => "Hierarquia",
        "BR.RevocationStatus" => "Status de revogação",
        "BR.ValidationTime" => "Validado em",
        "BR.SignaturePolicy" => "Política",
        "BR.SignaturePolicyStatus" => "Status da política",
        "BR.HolderType" => "Titular",
        "BR.Environment" => "Ambiente",
        "BR.CompanyName" => "Empresa",
        "BR.ResponsibleCpf" => "CPF do responsável",
        _ when key == Lei14063.MetadataKey => "Lei 14.063",
        _ => key.StartsWith("BR.", StringComparison.Ordinal) ? key[3..] : key,
    };

    private static AdesBaselineProfile Profile(SignatureLevel level, TimestampOptions? tsa) => level switch
    {
        SignatureLevel.Timestamped => AdesBaselineProfile.Timestamped(tsa!),
        SignatureLevel.LongTerm => AdesBaselineProfile.LongTerm(tsa!, new LongTermValidationOptions()),
        SignatureLevel.Archive => AdesBaselineProfile.Archive(tsa!, new LongTermValidationOptions()),
        _ => AdesBaselineProfile.Basic(),
    };
}
