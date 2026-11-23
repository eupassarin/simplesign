using System.Security.Cryptography;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Envelope;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Localization;

namespace SimpleSign.TestBench.Endpoints;

/// <summary>A signer of an envelope to prepare: an identifier given, or the SHA-256 of a credential's certificate.</summary>
public sealed record EnvelopeSignerRequest(
    string Name, string? CredentialId, string? IdentifierType, string? IdentifierValue, string? Role, string? Email, bool External,
    string Level, int Page, float X, float Y, float Width, float Height);

/// <summary>An envelope to prepare in a document.</summary>
public sealed record EnvelopePrepareRequest(
    string FileId, string Order, string? TsaUrl, string? Certify, bool LockDocument, IReadOnlyList<EnvelopeSignerRequest> Signers);

/// <summary>A field to sign: the credential, and how (the ICP-Brasil policy, a time-stamp server, a certification).</summary>
public sealed record EnvelopeSignRequest(string FileId, string Field, string CredentialId, string? IcpPolicy, string? TsaUrl, string? Certify);

/// <summary>A document with an envelope.</summary>
public sealed record EnvelopeFileRequest(string FileId);

/// <summary>A field as the Envelope tab shows it.</summary>
public sealed record EnvelopeFieldView(
    string Name, string? Signer, string? Role, string? Level, int? Page, bool IsSigned, string? SignedBy, DateTimeOffset? SigningTime,
    int? SignatureOrder, IReadOnlyList<string> ClaimedRoles);

/// <summary>An envelope as the Envelope tab shows it: the file it is in, where it stands, the manifest.</summary>
public sealed record EnvelopeView(
    string FileId, string FileName, string Status, string? Order, string? Next, IReadOnlyList<string> Problems,
    IReadOnlyList<EnvelopeFieldView> Fields, string? Manifest);

/// <summary>
/// The Envelope tab (ADR 0033): prepare an envelope in a document, sign its fields in turn with the credentials of the
/// workbench (a Sandbox signer, a PFX…), see where it stands, and validate it. Each step writes a new file, so every
/// stage can be downloaded.
/// </summary>
internal static class EnvelopeApi
{
    public static void Map(RouteGroupBuilder api)
    {
        var envelope = api.MapGroup("/envelope");
        envelope.MapGet("/levels", () => Levels.Select(l => new { l.Id, Baseline = l.Baseline.ToString(), l.Timestamp, l.SubFilters, l.PolicyOids }));
        envelope.MapPost("/prepare", (EnvelopePrepareRequest body, DocumentStore documents, CredentialStore credentials, CancellationToken ct) =>
            Answer(async () => Results.Ok(await PrepareAsync(body, documents, credentials, ct))));
        envelope.MapPost("/status", (EnvelopeFileRequest body, DocumentStore documents) =>
            Answer(() => Task.FromResult(Results.Ok(Status(body, documents)))));
        envelope.MapPost("/sign", (EnvelopeSignRequest body, DocumentStore documents, CredentialStore credentials, Sandbox.SandboxEnvironment sandbox, CancellationToken ct) =>
            Answer(async () => Results.Ok(await SignAsync(body, documents, credentials, sandbox, ct))));
        envelope.MapPost("/validate", (EnvelopeFileRequest body, DocumentStore documents, Sandbox.SandboxEnvironment sandbox, CancellationToken ct) =>
            Answer(async () => Results.Text((await ValidateAsync(body, documents, sandbox, ct)).ToJson(), "application/json")));
    }

    /// <summary>Prepares the envelope and stores the prepared file.</summary>
    internal static async Task<EnvelopeView> PrepareAsync(EnvelopePrepareRequest body, DocumentStore documents, CredentialStore credentials, CancellationToken ct)
    {
        var file = FileOf(body.FileId, documents);
        var builder = PdfEnvelope.Prepare(file.Content)
            .WithOrder(body.Order == "parallel" ? EnvelopeOrder.Parallel : EnvelopeOrder.Sequential);
        foreach (var signer in body.Signers)
        {
            builder = builder.AddSigner(Signer(signer, credentials));
        }

        if (!string.IsNullOrWhiteSpace(body.TsaUrl))
        {
            builder = builder.WithTimestampUrl(new Uri(body.TsaUrl));
        }

        if (Certification(body.Certify) is { } level)
        {
            builder = builder.WithCertification(level);
        }

        if (body.LockDocument)
        {
            builder = builder.WithDocumentLock();
        }

        byte[] prepared = await builder.PrepareAsync(ct);
        var stored = documents.Add(Path.GetFileNameWithoutExtension(file.FileName) + "-envelope.pdf", prepared);
        return View(stored.Id, stored.FileName, prepared);
    }

    /// <summary>Where the envelope of a stored file stands.</summary>
    internal static EnvelopeView Status(EnvelopeFileRequest body, DocumentStore documents)
    {
        var file = FileOf(body.FileId, documents);
        return PdfEnvelopeReader.Read(file.Content) is null
            ? throw new ArgumentException(L.T("The PDF holds no signature envelope."))
            : View(file.Id, file.FileName, file.Content);
    }

    /// <summary>Signs a field with a credential of the workbench and stores the signed file.</summary>
    internal static async Task<EnvelopeView> SignAsync(
        EnvelopeSignRequest body, DocumentStore documents, CredentialStore credentials, Sandbox.SandboxEnvironment sandbox, CancellationToken ct)
    {
        var file = FileOf(body.FileId, documents);
        if (!credentials.TryGet(body.CredentialId, out var credential))
        {
            throw new ArgumentException(L.T("Choose a credential."));
        }

        var builder = credential!.External is { } external
            ? PadesSigner.Document(file.Content).WithExternalSigner(credential.Certificate, external, credential.Chain)
            : PadesSigner.Document(file.Content).WithCertificate(credential.Certificate, credential.Chain);

        // The TestBench's HTTP provider lets the connected Sandbox's loopback services in (its TSA).
        builder = builder.WithHttpClientProvider(sandbox);
        var timestamp = string.IsNullOrWhiteSpace(body.TsaUrl) ? null : new TimestampOptions(new Uri(body.TsaUrl), sandbox);
        if (body.IcpPolicy is { Length: > 0 } policy)
        {
            builder = builder.WithCountryExtension(new IcpBrasilExtension())
                .WithIcpBrasilPolicy(policy == "ad-rt" ? IcpBrasilPolicy.AdRt : IcpBrasilPolicy.AdRb, timestamp);
        }
        else if (timestamp is not null)
        {
            builder = builder.WithLevel(AdesBaselineProfile.Timestamped(timestamp));
        }

        if (Certification(body.Certify) is { } level)
        {
            builder = builder.AsCertification(level);
        }

        byte[] signed = await builder.WithEnvelopeField(body.Field).SignAsync(ct);
        string name = Path.GetFileNameWithoutExtension(file.FileName).Replace("-envelope", "", StringComparison.Ordinal) + $"-{body.Field}.pdf";
        var stored = documents.Add(name, signed);
        return View(stored.Id, stored.FileName, signed);
    }

    /// <summary>Validates the envelope of a stored file, trusting the connected Sandbox's root (its certificates sign the fields here).</summary>
    internal static Task<PdfEnvelopeReport> ValidateAsync(EnvelopeFileRequest body, DocumentStore documents, Sandbox.SandboxEnvironment sandbox, CancellationToken ct)
    {
        var file = FileOf(body.FileId, documents);
        var root = sandbox.Current?.Root;
        var options = new SimpleSign.Core.Validation.ValidationOptions
        {
            CheckRevocation = false,
            Profile = IdentityProfile,
            TrustedRoots = root is null ? null : [root],
        };
        return new PdfEnvelopeValidator(options).ValidateAsync(file.Content, ct);
    }

    /// <summary>The answer of an endpoint: a missing file is a 404, a refusal or a wrong request a 400 with the reason.</summary>
    private static async Task<IResult> Answer(Func<Task<IResult>> action)
    {
        try
        {
            return await action();
        }
        catch (FileNotFoundException ex)
        {
            return Results.NotFound(new { error = ex.Message });
        }
        catch (SigningException ex)
        {
            return Results.BadRequest(new { error = ex.Message, reason = ex.Reason.ToString() });
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or FormatException or UriFormatException or CryptographicException)
        {
            return Results.BadRequest(new { error = ex.Message });
        }
    }

    private static StoredFile FileOf(string? id, DocumentStore documents) =>
        !string.IsNullOrEmpty(id) && documents.TryGet(id, out var file) ? file! : throw new FileNotFoundException(L.T("Choose a document."));

    /// <summary>The levels offered: the library's and ICP-Brasil's.</summary>
    internal static IReadOnlyList<EnvelopeLevel> Levels { get; } =
        [EnvelopeLevel.Any, EnvelopeLevel.PadesB, EnvelopeLevel.PadesT, EnvelopeLevel.PadesLt, EnvelopeLevel.PadesLta, IcpBrasilEnvelopeLevels.AdRb, IcpBrasilEnvelopeLevels.AdRt];

    /// <summary>The identity readers of the validation: ICP-Brasil's (CPF, CNPJ) besides the default one.</summary>
    private static TrustProfile IdentityProfile { get; } = TrustProfile.Default with { SignerIdentityReaders = new IcpBrasilExtension().SignerIdentityReaders };

    private static EnvelopeSigner Signer(EnvelopeSignerRequest request, CredentialStore credentials)
    {
        var level = Levels.FirstOrDefault(l => l.Id == request.Level)
            ?? throw new ArgumentException(L.T("Unknown level '{0}'.", request.Level));
        EnvelopeIdentifier? identifier = null;
        if (!string.IsNullOrWhiteSpace(request.IdentifierType) && !string.IsNullOrWhiteSpace(request.IdentifierValue))
        {
            identifier = new EnvelopeIdentifier(request.IdentifierType.Trim().ToUpperInvariant(), request.IdentifierValue.Trim());
        }
        else if (credentials.TryGet(request.CredentialId, out var credential))
        {
            identifier = new EnvelopeIdentifier(SignerIdentifierTypes.CertificateSha256, Convert.ToHexString(SHA256.HashData(credential!.Certificate.RawData)));
        }

        return new EnvelopeSigner
        {
            Name = request.Name,
            Role = string.IsNullOrWhiteSpace(request.Role) ? null : request.Role,
            Email = string.IsNullOrWhiteSpace(request.Email) ? null : request.Email,
            External = request.External,
            Level = level,
            Identifiers = identifier is null ? [] : [identifier],
            Placement = new EnvelopePlacement(request.Page, request.X, request.Y, request.Width, request.Height),
        };
    }

    private static CertificationLevel? Certification(string? value) => value switch
    {
        "form-filling" => CertificationLevel.FormFilling,
        "annotations" => CertificationLevel.FormFillingAndAnnotations,
        "no-changes" => CertificationLevel.NoChanges,
        _ => null,
    };

    private static EnvelopeView View(string fileId, string fileName, byte[] pdf)
    {
        var envelope = PdfEnvelopeReader.Read(pdf)!;
        return new EnvelopeView(
            fileId, fileName, envelope.Status.ToString(), envelope.Manifest?.Order.ToString(), envelope.Next?.Name, envelope.Problems,
            [.. envelope.Fields.Select(f => new EnvelopeFieldView(
                f.Name, f.Signer?.Name, f.Signer?.Role, f.Signer?.Level.Id, f.Placement?.Page, f.IsSigned, f.SignerName, f.SigningTime,
                f.SignatureOrder, f.ClaimedRoles))],
            envelope.Manifest?.ToJson());
    }
}
