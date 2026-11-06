using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.Brazil.Signing;
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
    private readonly DocumentStore _documents;
    private readonly PlanContext _context;

    public SigningPlan(SigningOptions effective, CredentialHandle credential, SandboxEnvironment sandbox, DocumentStore documents)
    {
        _o = effective;
        _credential = credential;
        _documents = documents;
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

    /// <summary>The baseline profile (null for ICP-Brasil, whose extension builds the profile).</summary>
    public AdesBaselineProfile? Profile { get; }

    public TimestampOptions? Timestamp { get; private set; }

    public ArchiveTimestampOptions? ArchiveTimestamp { get; private set; }

    /// <summary>Statements that must run before the builder chain (variables, clients).</summary>
    public IReadOnlyList<string> Setup => _context.Setup;

    /// <summary>The builder steps after <c>PadesSigner.Document(pdf)</c>, in order.</summary>
    public async Task<IReadOnlyList<PlanStep>> SignStepsAsync(CancellationToken cancellationToken)
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
            steps.Add(_o.SignerDetails == SignerDetailsKind.Aea ? AeaStep() : MetadataStep());
        }

        switch (_o.Kind)
        {
            case SignatureKind.IcpBrasil:
                steps.Add(await IcpStepAsync(cancellationToken));
                break;
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

        if (_o.Health.Enabled && _o.FieldMode == FieldMode.New)
        {
            var professionals = _o.Health.Professionals.Select(p => new ProfessionalRegistration(
                Enum.Parse<ProfessionalCouncil>(p.Council), p.RegistrationNumber, Blank(p.StateCode), Blank(p.Specialty))).ToArray();
            var type = Enum.Parse<HealthDocumentType>(_o.Health.Type);
            string list = string.Join(", ", professionals.Select(p =>
                $"new ProfessionalRegistration(ProfessionalCouncil.{p.Council}, {Str(p.RegistrationNumber)}, {Str(p.StateCode)}, {Str(p.Specialty)})"));
            steps.Add(new($".WithHealthDocument(HealthDocumentType.{type}, {list})", b => b.WithHealthDocument(type, professionals)));
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

    private PlanStep AeaStep()
    {
        var a = _o.Aea;
        var info = new AdvancedSignatureInfo
        {
            SignerName = a.SignerName,
            Cpf = string.Concat(a.Cpf.Where(char.IsAsciiDigit)),
            AuthMethod = Enum.Parse<AuthenticationMethod>(a.AuthMethod),
            Email = Blank(a.Email),
            IpAddress = Blank(a.IpAddress),
            CommitmentType = Enum.Parse<CommitmentType>(a.CommitmentType),
            InstitutionName = Blank(a.InstitutionName),
            InstitutionCnpj = Blank(a.InstitutionCnpj),
            PolicyOid = Blank(a.PolicyOid),
            PolicyUri = Blank(a.PolicyUri),
        };
        var sb = new StringBuilder(".WithAdvancedSignature(new AdvancedSignatureInfo\n    {\n");
        Prop(sb, "SignerName", info.SignerName);
        Prop(sb, "Cpf", info.Cpf);
        sb.Append(CultureInfo.InvariantCulture, $"        AuthMethod = AuthenticationMethod.{info.AuthMethod},\n");
        Prop(sb, "Email", info.Email);
        Prop(sb, "IpAddress", info.IpAddress);
        sb.Append(CultureInfo.InvariantCulture, $"        CommitmentType = CommitmentType.{info.CommitmentType},\n");
        Prop(sb, "InstitutionName", info.InstitutionName);
        Prop(sb, "InstitutionCnpj", info.InstitutionCnpj);
        Prop(sb, "PolicyOid", info.PolicyOid);
        Prop(sb, "PolicyUri", info.PolicyUri);
        sb.Append("    })");
        return new(sb.ToString(), b => b.WithAdvancedSignature(info));
    }

    private async Task<PlanStep> IcpStepAsync(CancellationToken cancellationToken)
    {
        var policy = _o.IcpPolicy switch
        {
            IcpPolicyKind.AdRb => IcpBrasilPolicy.AdRb,
            IcpPolicyKind.AdRt => IcpBrasilPolicy.AdRt,
            IcpPolicyKind.AdRc => IcpBrasilPolicy.AdRc,
            _ => IcpBrasilPolicy.AdRa,
        };
        IcpBrasilSignaturePolicy? version = null;
        if (!string.IsNullOrWhiteSpace(_o.IcpVersionOid))
        {
            if (!IcpBrasilSignaturePolicies.TryFind(_o.IcpVersionOid, out version))
            {
                throw new ArgumentException($"Unknown ICP-Brasil policy {_o.IcpVersionOid}.");
            }
        }

        bool needsTsa = policy != IcpBrasilPolicy.AdRb || _o.IcpAdRbTimestamp;
        bool longTerm = policy is IcpBrasilPolicy.AdRc or IcpBrasilPolicy.AdRa;
        if (needsTsa)
        {
            Timestamp = BuildTimestamp(_o.Timestamp, "tsa");
        }

        if (longTerm && _o.SeparateArchiveTsa)
        {
            ArchiveTimestamp = BuildArchive(_o.ArchiveTimestamp);
        }

        IcpBrasilPolicyArtifacts? artifacts = null;
        string artifactsCode = "";
        if (policy == IcpBrasilPolicy.AdRa)
        {
            var resolved = version ?? IcpBrasilSignaturePolicies.Current(policy, IcpBrasilPolicyFormat.Pades);
            if (IsSandbox)
            {
                // Simulated: the PA, LPA and LPA signature of a real AD-RA are downloaded from the ITI.
                byte[] Fake(string name) => Encoding.ASCII.GetBytes($"SimpleSign sandbox {name} for {resolved.Oid}");
                artifacts = new IcpBrasilPolicyArtifacts(resolved, Fake("PA"), Fake("LPA"), Fake("LPA signature"));
            }
            else
            {
                using var http = new HttpClient();
                artifacts = await IcpBrasilPolicyArtifacts.DownloadAsync(http, resolved, cancellationToken);
            }

            // The artifacts must be those of the version the signature will carry.
            _context.AddSetup("using var http = new HttpClient();\n"
                + (version is null
                    ? "var adRa = PadesSigner.Document(pdf).WithCertificate(certificate, chain).ResolveIcpBrasilPolicy(IcpBrasilPolicy.AdRa); // the version picked by the signer's root\n"
                    : $"var adRa = IcpBrasilSignaturePolicies.All.Single(p => p.Oid == \"{version.Oid}\");\n")
                + "var artifacts = await IcpBrasilPolicyArtifacts.DownloadAsync(http, adRa); // PA, LPA and LPA signature from the ITI (LPA signature verified)"
                + (IsSandbox ? "\n// (the sandbox embeds simulated artifacts instead)" : ""));
            artifactsCode = "\n        Artifacts = artifacts,";
        }

        var options = new IcpBrasilPadesOptions
        {
            Timestamp = Timestamp,
            ArchiveTimestamp = ArchiveTimestamp,
            LongTermValidation = longTerm ? _context.BuildLongTerm(_o.RevocationPreference) : null,
            Version = version,
            Artifacts = artifacts,
        };
        string code = $".WithIcpBrasilPolicy(IcpBrasilPolicy.{policy}, new IcpBrasilPadesOptions\n    {{"
            + (Timestamp is not null ? "\n        Timestamp = tsa," : "")
            + (ArchiveTimestamp is not null ? "\n        ArchiveTimestamp = archiveTsa," : "")
            + (longTerm ? $"\n        LongTermValidation = {_context.LongTermCode(_o.RevocationPreference)}," : "")
            + (version is not null ? $"\n        Version = IcpBrasilSignaturePolicies.All.Single(p => p.Oid == \"{version.Oid}\")," : "")
            + artifactsCode
            + "\n    })";
        return new(code, b => b.WithIcpBrasilPolicy(policy, options));
    }

    private AdesBaselineProfile? BuildProfile()
    {
        if (_o.Kind == SignatureKind.IcpBrasil)
        {
            return null;
        }

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
                SubFilterChoice.PbadPades => PdfSignatureSubFilter.PbadPades,
                _ => PdfSignatureSubFilter.EtsiCadesDetached,
            },
            Appearance = _o.Appearance.Visible ? BuildAppearance(_o.Appearance, existing) : null,
            CertificationLevel = _o.Certification switch
            {
                CertificationChoice.NoChanges => CertificationLevel.NoChanges,
                CertificationChoice.FormFilling => CertificationLevel.FormFilling,
                CertificationChoice.FormFillingAndAnnotations => CertificationLevel.FormFillingAndAnnotations,
                _ => null,
            },
        };
    }

    internal SignatureAppearance BuildAppearance(AppearanceChoice a, bool existing)
    {
        byte[]? image = string.IsNullOrEmpty(a.ImageUploadId) ? null : _documents.Get(a.ImageUploadId).Content;
        bool isPng = image is { Length: > 8 } && image[0] == 0x89 && image[1] == (byte)'P';
        return new SignatureAppearance
        {
            Page = a.Page,
            X = a.X,
            Y = a.Y,
            Width = a.Width,
            Height = a.Height,
            AutoPosition = a.AutoPosition && !existing,
            TextAlignment = Enum.Parse<SignatureTextAlignment>(a.TextAlignment),
            VerticalAlignment = Enum.Parse<SignatureVerticalAlignment>(a.VerticalAlignment),
            ShrinkToFit = a.ShrinkToFit,
            MaxTextLength = a.MaxTextLength,
            ShowDate = a.ShowDate,
            ShowReason = a.ShowReason,
            ShowLocation = a.ShowLocation,
            SignedByLabel = a.SignedByLabel ?? "Signed by",
            ReasonLabel = a.ReasonLabel ?? "Reason: ",
            LocationLabel = a.LocationLabel ?? "Location: ",
            DateLabel = a.DateLabel ?? string.Empty,
            SignerDisplayName = Blank(a.SignerDisplayName),
            ExtraLines = a.ExtraLines.Count > 0 ? a.ExtraLines : null,
            DateFormat = Blank(a.DateFormat),
            TimeZone = string.IsNullOrWhiteSpace(a.TimeZoneId) ? null : TimeZoneInfo.FindSystemTimeZoneById(a.TimeZoneId),
            DateCulture = string.IsNullOrWhiteSpace(a.Culture) ? null : CultureInfo.GetCultureInfo(a.Culture),
            BackgroundColor = Color(a.BackgroundColor),
            TextColor = Color(a.TextColor),
            BorderColor = Color(a.BorderColor),
            BorderWidth = a.BorderWidth,
            BaseFontName = a.BaseFont,
            CustomFontSize = a.FontSize,
            CustomLabelFontSize = a.LabelFontSize,
            VerificationUrl = Blank(a.VerificationUrl),
            BackgroundImagePng = isPng ? image : null,
            BackgroundImageJpeg = image is not null && !isPng ? image : null,
            BackgroundImageFit = Enum.Parse<SignatureImageFit>(a.ImageFit),
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

        if (f.Appearance is not null)
        {
            sb.Append("        Appearance = ").Append(AppearanceCode(_o.Appearance, f.ExistingFieldName is not null).Replace("\n", "\n    ", StringComparison.Ordinal)).Append(",\n");
        }

        sb.Append("    }");
        return sb.ToString();
    }

    private static string AppearanceCode(AppearanceChoice a, bool existing)
    {
        var defaults = new AppearanceChoice();
        var sb = new StringBuilder("new SignatureAppearance\n    {\n");
        if (!existing)
        {
            if (a.AutoPosition)
            {
                sb.Append("        AutoPosition = true,\n");
            }
            else
            {
                sb.Append(CultureInfo.InvariantCulture, $"        Page = {a.Page}, X = {a.X:0.##}f, Y = {a.Y:0.##}f, Width = {a.Width:0.##}f, Height = {a.Height:0.##}f,\n");
            }
        }

        void Enum(string name, string value, string def)
        {
            if (value != def)
            {
                sb.Append(CultureInfo.InvariantCulture, $"        {name} = Signature{name}.{value},\n");
            }
        }

        Enum("TextAlignment", a.TextAlignment, "Left");
        Enum("VerticalAlignment", a.VerticalAlignment, "Top");
        if (!a.ShrinkToFit)
        {
            sb.Append("        ShrinkToFit = false,\n");
        }

        if (a.MaxTextLength != defaults.MaxTextLength)
        {
            sb.Append(CultureInfo.InvariantCulture, $"        MaxTextLength = {a.MaxTextLength},\n");
        }

        if (!a.ShowDate)
        {
            sb.Append("        ShowDate = false,\n");
        }

        if (a.ShowReason)
        {
            sb.Append("        ShowReason = true,\n");
        }

        if (a.ShowLocation)
        {
            sb.Append("        ShowLocation = true,\n");
        }

        Prop(sb, "SignedByLabel", a.SignedByLabel);
        Prop(sb, "ReasonLabel", a.ReasonLabel);
        Prop(sb, "LocationLabel", a.LocationLabel);
        Prop(sb, "DateLabel", a.DateLabel);
        Prop(sb, "SignerDisplayName", Blank(a.SignerDisplayName));
        if (a.ExtraLines.Count > 0)
        {
            sb.Append("        ExtraLines = [").Append(string.Join(", ", a.ExtraLines.Select(Str))).Append("],\n");
        }

        Prop(sb, "DateFormat", Blank(a.DateFormat));
        if (!string.IsNullOrWhiteSpace(a.TimeZoneId))
        {
            sb.Append(CultureInfo.InvariantCulture, $"        TimeZone = TimeZoneInfo.FindSystemTimeZoneById({Str(a.TimeZoneId)}),\n");
        }

        if (!string.IsNullOrWhiteSpace(a.Culture))
        {
            sb.Append(CultureInfo.InvariantCulture, $"        DateCulture = CultureInfo.GetCultureInfo({Str(a.Culture)}),\n");
        }

        foreach (var (name, value) in new[] { ("BackgroundColor", a.BackgroundColor), ("TextColor", a.TextColor), ("BorderColor", a.BorderColor) })
        {
            if (Color(value) is { } c)
            {
                sb.Append(CultureInfo.InvariantCulture, $"        {name} = ({c.R:0.###}f, {c.G:0.###}f, {c.B:0.###}f),\n");
            }
        }

        if (Math.Abs(a.BorderWidth - 0.5f) > 0.001f)
        {
            sb.Append(CultureInfo.InvariantCulture, $"        BorderWidth = {a.BorderWidth:0.##}f,\n");
        }

        if (a.BaseFont != "Helvetica")
        {
            Prop(sb, "BaseFontName", a.BaseFont);
        }

        if (a.FontSize is { } size)
        {
            sb.Append(CultureInfo.InvariantCulture, $"        CustomFontSize = {size:0.##}f,\n");
        }

        if (a.LabelFontSize is { } labelSize)
        {
            sb.Append(CultureInfo.InvariantCulture, $"        CustomLabelFontSize = {labelSize:0.##}f,\n");
        }

        Prop(sb, "VerificationUrl", Blank(a.VerificationUrl));
        if (!string.IsNullOrEmpty(a.ImageUploadId))
        {
            sb.Append("        BackgroundImagePng = File.ReadAllBytes(\"stamp.png\"), // or BackgroundImageJpeg\n");
            Enum("ImageFit", a.ImageFit, "Stretch");
        }

        sb.Append("    }");
        return sb.ToString().Replace("SignatureImageFit = SignatureImageFit", "BackgroundImageFit = SignatureImageFit", StringComparison.Ordinal);
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

    private static string HashOid(HashChoice hash) => hash switch
    {
        HashChoice.Sha384 => "2.16.840.1.101.3.4.2.2",
        HashChoice.Sha512 => "2.16.840.1.101.3.4.2.3",
        HashChoice.Sha3_256 => "2.16.840.1.101.3.4.2.8",
        HashChoice.Sha3_384 => "2.16.840.1.101.3.4.2.9",
        HashChoice.Sha3_512 => "2.16.840.1.101.3.4.2.10",
        _ => "2.16.840.1.101.3.4.2.1",
    };

    internal static (float R, float G, float B)? Color(string? hex)
    {
        if (string.IsNullOrWhiteSpace(hex))
        {
            return null;
        }

        string h = hex.TrimStart('#');
        if (h.Length != 6 || !h.All(char.IsAsciiHexDigit))
        {
            return null;
        }

        float Part(int i) => int.Parse(h.AsSpan(i, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture) / 255f;
        return (Part(0), Part(2), Part(4));
    }

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
