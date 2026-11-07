using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestBench.Credentials;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Sandbox;

namespace SimpleSign.TestBench.Signing;

/// <summary>One builder call: the C# it corresponds to and the call itself.</summary>
internal sealed record PlanStep(string Code, Func<PadesSignerBuilder, PadesSignerBuilder> Apply);

/// <summary>
/// Turns <see cref="SigningOptions"/> into library objects and builder calls. Each call carries
/// the C# that produces it, so the Code tab shows exactly what ran.
/// </summary>
internal sealed class SigningPlan
{
    private readonly SigningOptions _o;
    private readonly CredentialHandle _credential;
    private readonly PlanContext _context;

    public SigningPlan(SigningOptions effective, CredentialHandle credential, SandboxEnvironment sandbox, DocumentStore documents)
    {
        _o = effective;
        _credential = credential;
        _context = new PlanContext(effective.Environment, credential, sandbox, documents);
        IsSandbox = _context.IsSandbox;
        Http = _context.Http;
        HashAlgorithm = ToHash(effective.Hash);
        SignatureAlgorithmOid = _credential.Facts.KeyAlgorithm == "RSA" && effective.Padding == RsaPadding.Pss ? Oids.RsaPss : null;
        Field = BuildField();
        Profile = BuildProfile();
    }

    public bool IsSandbox { get; }

    public IHttpClientProvider Http { get; }

    public HashAlgorithmName HashAlgorithm { get; }

    public string? SignatureAlgorithmOid { get; }

    public SignatureFieldOptions Field { get; }

    /// <summary>The baseline profile.</summary>
    public AdesBaselineProfile? Profile { get; }

    public TimestampOptions? Timestamp { get; private set; }

    public ArchiveTimestampOptions? ArchiveTimestamp { get; private set; }

    /// <summary>Statements that must run before the builder chain (variables, clients).</summary>
    public IReadOnlyList<string> Setup => _context.Setup;

    /// <summary>The builder steps after <c>PadesSigner.Document(pdf)</c>, in order.</summary>
    public IReadOnlyList<PlanStep> SignSteps()
    {
        var steps = new List<PlanStep>();
        steps.Add(CredentialStep());
        if (!IsSandbox || _o.Environment == EnvironmentMode.Sandbox)
        {
            steps.Add(new(IsSandbox ? ".WithHttpClientProvider(sandboxHttp) // TSA and CRLs on *.sandbox.simplesign.test" : "// default HttpClient provider (real network)",
                b => b.WithHttpClientProvider(Http)));
        }

        steps.Add(new($".WithFieldOptions({FieldCode()})", b => b.WithFieldOptions(Field)));
        if (HashAlgorithm != HashAlgorithmName.SHA256)
        {
            steps.Add(new($".WithHashAlgorithm(HashAlgorithmName.{HashName(_o.Hash)})", b => b.WithHashAlgorithm(HashAlgorithm)));
        }

        if (_o.SigningPolicy != SigningPolicyChoice.Default)
        {
            var policy = ToSigningPolicy(_o.SigningPolicy);
            steps.Add(new(SigningPolicyCode(_o.SigningPolicy), b => b.WithSigningPolicy(policy)));
        }

        if (SignatureAlgorithmOid is { } oid)
        {
            steps.Add(new(".WithSignatureAlgorithm(Oids.RsaPss) // RSASSA-PSS, salt = hash length", b => b.WithSignatureAlgorithm(oid)));
        }

        if (_o.SigningTime is { } time)
        {
            steps.Add(new($".WithSigningTime(DateTimeOffset.Parse(\"{time:O}\"))", b => b.WithSigningTime(time)));
        }

        if (_o.UseSignerDetails)
        {
            steps.Add(MetadataStep());
        }

        switch (_o.Kind)
        {
            case SignatureKind.CustomPolicy:
                var policy = new SignaturePolicyReference(_o.CustomPolicy.Oid, HashOid(_o.CustomPolicy.HashAlgorithm), Convert.FromHexString(_o.CustomPolicy.HashHex),
                    string.IsNullOrWhiteSpace(_o.CustomPolicy.Uri) ? null : _o.CustomPolicy.Uri);
                steps.Add(new($".WithSignaturePolicy(new SignaturePolicyReference(\"{policy.Oid}\", \"{policy.HashAlgorithmOid}\", Convert.FromHexString(\"{_o.CustomPolicy.HashHex}\"), {Str(policy.Uri)}))",
                    b => b.WithSignaturePolicy(policy)));
                steps.Add(new($".WithLevel({ProfileCode()})", b => b.WithLevel(Profile!)));
                break;
            default:
                steps.Add(new($".WithLevel({ProfileCode()})", b => b.WithLevel(Profile!)));
                break;
        }

        if (_o.FieldMode == FieldMode.New)
        {
            foreach (var entry in _o.DocumentInfo.Where(e => !string.IsNullOrWhiteSpace(e.Key)))
            {
                steps.Add(new($".WithDocumentInfo({Str(entry.Key)}, {Str(entry.Value)})", b => b.WithDocumentInfo(entry.Key, entry.Value)));
            }
        }

        if (_o.PreservePdfA)
        {
            steps.Add(new(".WithPdfAPreservation()", b => b.WithPdfAPreservation()));
        }

        if (!string.IsNullOrWhiteSpace(_o.OperationId))
        {
            steps.Add(new($".WithOperationId({Str(_o.OperationId)})", b => b.WithOperationId(_o.OperationId!)));
        }

        return steps;
    }

    private PlanStep CredentialStep()
    {
        string code = _context.CredentialCode();
        return _credential.External is { } external
            ? new(code, b => b.WithExternalSigner(_credential.Certificate, external, _credential.Chain))
            : new(code, b => b.WithCertificate(_credential.Certificate, _credential.Chain));
    }

    private PlanStep MetadataStep()
    {
        var m = _o.Metadata;
        bool basePolicy = _o.Kind == SignatureKind.Baseline;
        var metadata = new SignatureMetadata
        {
            SignerName = m.SignerName ?? _credential.Facts.Holder,
            SignerId = Blank(m.SignerId),
            SignerIdType = Blank(m.SignerIdType),
            Email = Blank(m.Email),
            IpAddress = Blank(m.IpAddress),
            AuthenticationMethod = Blank(m.AuthenticationMethod),
            InstitutionName = Blank(m.InstitutionName),
            InstitutionId = Blank(m.InstitutionId),
            InstitutionIdType = Blank(m.InstitutionIdType),
            CommitmentType = Enum.Parse<CommitmentType>(m.CommitmentType),
            LegalBasis = Blank(m.LegalBasis),
            PolicyOid = basePolicy ? Blank(m.PolicyOid) : null,
            PolicyUri = basePolicy ? Blank(m.PolicyUri) : null,
            Reason = Blank(_o.Reason),
            Location = Blank(_o.Location),
            ContactInfo = Blank(_o.ContactInfo),
        };
        var sb = new StringBuilder(".WithMetadata(new SignatureMetadata\n    {\n");
        Prop(sb, "SignerName", metadata.SignerName);
        Prop(sb, "SignerId", metadata.SignerId);
        Prop(sb, "SignerIdType", metadata.SignerIdType);
        Prop(sb, "Email", metadata.Email);
        Prop(sb, "IpAddress", metadata.IpAddress);
        Prop(sb, "AuthenticationMethod", metadata.AuthenticationMethod);
        Prop(sb, "InstitutionName", metadata.InstitutionName);
        Prop(sb, "InstitutionId", metadata.InstitutionId);
        Prop(sb, "InstitutionIdType", metadata.InstitutionIdType);
        sb.Append(CultureInfo.InvariantCulture, $"        CommitmentType = CommitmentType.{metadata.CommitmentType},\n");
        Prop(sb, "LegalBasis", metadata.LegalBasis);
        Prop(sb, "PolicyOid", metadata.PolicyOid);
        Prop(sb, "PolicyUri", metadata.PolicyUri);
        Prop(sb, "Reason", metadata.Reason);
        Prop(sb, "Location", metadata.Location);
        Prop(sb, "ContactInfo", metadata.ContactInfo);
        sb.Append("    })");
        return new(sb.ToString(), b => b.WithMetadata(metadata));
    }

    private AdesBaselineProfile? BuildProfile()
    {
        var failure = _o.ReturnLowerLevel && _o.Mode == RunMode.Sign ? SigningLevelFailureBehavior.ReturnLowerLevel : SigningLevelFailureBehavior.Throw;
        switch (_o.Level)
        {
            case BaselineLevel.BB:
                return AdesBaselineProfile.Basic();
            case BaselineLevel.BT:
                Timestamp = BuildTimestamp(_o.Timestamp, "tsa");
                return AdesBaselineProfile.Timestamped(Timestamp, failure);
            case BaselineLevel.BLT:
                Timestamp = BuildTimestamp(_o.Timestamp, "tsa");
                return AdesBaselineProfile.LongTerm(Timestamp, _context.BuildLongTerm(_o.RevocationPreference), failure);
            default:
                Timestamp = BuildTimestamp(_o.Timestamp, "tsa");
                ArchiveTimestamp = _o.SeparateArchiveTsa ? BuildArchive(_o.ArchiveTimestamp) : null;
                return AdesBaselineProfile.Archive(Timestamp, _context.BuildLongTerm(_o.RevocationPreference), ArchiveTimestamp, failure);
        }
    }

    public string ProfileCode()
    {
        string failure = _o.ReturnLowerLevel && _o.Mode == RunMode.Sign ? ", SigningLevelFailureBehavior.ReturnLowerLevel" : "";
        string ltv = _context.LongTermCode(_o.RevocationPreference);
        return _o.Level switch
        {
            BaselineLevel.BB => "AdesBaselineProfile.Basic()",
            BaselineLevel.BT => $"AdesBaselineProfile.Timestamped(tsa{failure})",
            BaselineLevel.BLT => $"AdesBaselineProfile.LongTerm(tsa, {ltv}{failure})",
            _ => $"AdesBaselineProfile.Archive(tsa, {ltv}{(ArchiveTimestamp is not null ? ", archiveTsa" : failure.Length > 0 ? ", null" : "")}{failure})",
        };
    }

    private TimestampOptions BuildTimestamp(TimestampChoice choice, string variable) => _context.BuildTimestamp(choice, variable);

    private ArchiveTimestampOptions BuildArchive(TimestampChoice choice) => _context.BuildArchive(choice);

    private SignatureFieldOptions BuildField()
    {
        bool existing = _o.FieldMode == FieldMode.Existing;
        return new SignatureFieldOptions
        {
            FieldName = existing ? _o.ExistingFieldName! : _o.FieldName,
            ExistingFieldName = existing ? _o.ExistingFieldName : null,
            SignerName = Blank(_o.SignerName),
            Reason = Blank(_o.Reason),
            Location = Blank(_o.Location),
            ContactInfo = Blank(_o.ContactInfo),
            ContentsReservedBytes = _o.ContentsReservedBytes ?? 16384,
            SubFilter = _o.SubFilter switch
            {
                SubFilterChoice.AdbePkcs7Detached => PdfSignatureSubFilter.AdbePkcs7Detached,
                _ => PdfSignatureSubFilter.EtsiCadesDetached,
            },
            CertificationLevel = _o.Certification switch
            {
                CertificationChoice.NoChanges => CertificationLevel.NoChanges,
                CertificationChoice.FormFilling => CertificationLevel.FormFilling,
                CertificationChoice.FormFillingAndAnnotations => CertificationLevel.FormFillingAndAnnotations,
                _ => null,
            },
        };
    }

    public string FieldCode()
    {
        var f = Field;
        var sb = new StringBuilder("new SignatureFieldOptions\n    {\n");
        if (f.ExistingFieldName is not null)
        {
            Prop(sb, "ExistingFieldName", f.ExistingFieldName);
        }
        else
        {
            Prop(sb, "FieldName", f.FieldName);
        }

        Prop(sb, "SignerName", f.SignerName);
        Prop(sb, "Reason", f.Reason);
        Prop(sb, "Location", f.Location);
        Prop(sb, "ContactInfo", f.ContactInfo);
        if (f.ContentsReservedBytes != 16384)
        {
            sb.Append(CultureInfo.InvariantCulture, $"        ContentsReservedBytes = {f.ContentsReservedBytes},\n");
        }

        if (f.SubFilter != PdfSignatureSubFilter.EtsiCadesDetached)
        {
            sb.Append(CultureInfo.InvariantCulture, $"        SubFilter = PdfSignatureSubFilter.{f.SubFilter},\n");
        }

        if (f.CertificationLevel is { } level)
        {
            sb.Append(CultureInfo.InvariantCulture, $"        CertificationLevel = CertificationLevel.{level},\n");
        }

        sb.Append("    }");
        return sb.ToString();
    }

    internal static HashAlgorithmName ToHash(HashChoice hash) => hash switch
    {
        HashChoice.Sha384 => HashAlgorithmName.SHA384,
        HashChoice.Sha512 => HashAlgorithmName.SHA512,
        HashChoice.Sha3_256 => HashAlgorithmName.SHA3_256,
        HashChoice.Sha3_384 => HashAlgorithmName.SHA3_384,
        HashChoice.Sha3_512 => HashAlgorithmName.SHA3_512,
        _ => HashAlgorithmName.SHA256,
    };

    internal static string HashName(HashChoice hash) => ToHash(hash).Name!;

    /// <summary>The library policy of a choice.</summary>
    internal static SigningPolicy ToSigningPolicy(SigningPolicyChoice choice) => choice switch
    {
        SigningPolicyChoice.Strict => SigningPolicy.Strict,
        SigningPolicyChoice.Minimal => SigningPolicy.Minimal,
        _ => SigningPolicy.Default,
    };

    /// <summary>The builder call of a policy choice other than the default.</summary>
    internal static string SigningPolicyCode(SigningPolicyChoice choice) => choice switch
    {
        SigningPolicyChoice.Strict => ".WithSigningPolicy(SigningPolicy.Strict) // also checks the revocation of the chain",
        _ => ".WithSigningPolicy(SigningPolicy.Minimal) // only the signing certificate's dates",
    };

    private static string HashOid(HashChoice hash) => hash switch
    {
        HashChoice.Sha384 => "2.16.840.1.101.3.4.2.2",
        HashChoice.Sha512 => "2.16.840.1.101.3.4.2.3",
        HashChoice.Sha3_256 => "2.16.840.1.101.3.4.2.8",
        HashChoice.Sha3_384 => "2.16.840.1.101.3.4.2.9",
        HashChoice.Sha3_512 => "2.16.840.1.101.3.4.2.10",
        _ => "2.16.840.1.101.3.4.2.1",
    };

    internal static string? Blank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;

    /// <summary>Adds <c>Name = "value"</c> to the fields of an object initializer when the value is set.</summary>
    internal static void AddField(List<string> fields, string name, string? value)
    {
        if (value is not null)
        {
            fields.Add($"{name} = {Str(value)}");
        }
    }

    internal static string Str(string? value) =>
        value is null ? "null" : "\"" + value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal).Replace("\n", "\\n", StringComparison.Ordinal) + "\"";

    private static void Prop(StringBuilder sb, string name, string? value)
    {
        if (value is not null)
        {
            sb.Append(CultureInfo.InvariantCulture, $"        {name} = {Str(value)},\n");
        }
    }
}
