using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Validation;
using SimpleSign.XAdES.TrustedLists;

namespace SimpleSign.Europe.Eidas;

/// <summary>
/// The EU qualification of a validated signature: ETSI TS 119 615 says, from the trusted lists, whether the signer's
/// certificate is qualified, for signatures or seals, with its key on a QSCD; ETSI TS 119 172-4 turns that and the
/// validation's indication into QESig, QESeal, AdESig-QC, AdESeal-QC, AdESig or AdESeal. Each timestamp is a qualified
/// electronic time-stamp when a granted TSA/QTST service of the lists issued it.
/// </summary>
/// <remarks>
/// <list type="number">
/// <item>The trust service: the CA/QC or CA/PKC service whose certificate the signer's chain reaches (by issuer name,
/// through the certificates of the signature).</item>
/// <item>At the certificate's issuance (its notBefore): the service then in force must be a granted CA/QC; its
/// Qualifications that apply to the certificate correct its QC statements (QCStatement / NotQualified, QCForESig /
/// QCForESeal / QCForWSA). A certificate under a non-EU legislation (QcCClegislation) is not EU qualified.</item>
/// <item>At the signing time (the best signature time, else the claimed one): the service must still be granted, and
/// its Qualifications then say whether the key is on a QSCD (QCWithQSCD / QCNoQSCD / QCQSCDStatusAsInCert / QCWithSSCD
/// / QCNoSSCD / QCQSCDManagedOnBehalf), else the certificate's QcSSCD does.</item>
/// <item>TS 119 172-4: valid → the level; indeterminate → "Indeterminate" and the level; failed → Not AdES.</item>
/// </list>
/// </remarks>
public sealed class EidasQualifier : ISignatureQualifier
{
    private const string QualifierPrefix = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/";
    private const string EtsiUriPrefix = "urn:cef:dss:signatureQualification:";
    private static readonly string[] ActiveStatuses = ["/granted", "/undersupervision", "/accredited", "/supervisionincessation"];

    private readonly Func<IReadOnlyList<TrustedList>> _lists;

    /// <summary>A qualifier over the trusted lists <paramref name="lists"/> gives each time it qualifies (the current ones of a refreshed source).</summary>
    /// <param name="lists">The national trusted lists.</param>
    public EidasQualifier(Func<IReadOnlyList<TrustedList>> lists)
    {
        ArgumentNullException.ThrowIfNull(lists);
        _lists = lists;
    }

    /// <summary>A qualifier over the lists of <paramref name="set"/>.</summary>
    /// <param name="set">The LOTL and its lists.</param>
    public EidasQualifier(TrustedListSet set)
    {
        ArgumentNullException.ThrowIfNull(set);
        _lists = () => set.Lists;
    }

    /// <inheritdoc />
    public SignatureQualification? Qualify(SignatureQualificationContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var lists = _lists();
        var notes = new List<string>();
        var timestamps = Timestamps(context, lists);
        var signer = context.SignerCertificate;
        var service = CaService(signer, context.Certificates, lists);
        if (service is null)
        {
            notes.Add("No CA service of the EU trusted lists issued the signer's certificate: not under eIDAS.");
            return Result(SignatureQualificationLevels.NotApplicable, notes, timestamps);
        }

        notes.Add($"Trust service: {service.ServiceName} ({service.ProviderName}), {Last(service.ServiceType)}.");
        var statements = QcStatements.Decode(signer);
        var issuance = new DateTimeOffset(signer.NotBefore.ToUniversalTime());
        var signingTime = context.BestSignatureTime ?? context.ClaimedSigningTime ?? DateTimeOffset.UtcNow;

        // TS 119 615 §4.3: the certificate's qualification at its issuance.
        var atIssuance = service.InformationAt(issuance);
        bool qcAtIssuance = false;
        string type = TypeOf(statements, service.Extensions);
        if (atIssuance is null || !IsActive(atIssuance.Status) || !IsCaQc(atIssuance.ServiceType ?? service.ServiceType))
        {
            notes.Add($"At issuance ({issuance:yyyy-MM-dd}) the service was not a granted CA/QC: the certificate is not qualified.");
        }
        else
        {
            var qualifiers = atIssuance.Extensions.QualifiersFor(signer);
            qcAtIssuance = statements.QcCompliance;
            if (Has(qualifiers, "QCStatement"))
            {
                qcAtIssuance = true;
                notes.Add("The trusted list declares it qualified (QCStatement).");
            }

            if (Has(qualifiers, "NotQualified"))
            {
                qcAtIssuance = false;
                notes.Add("The trusted list declares it not qualified (NotQualified).");
            }

            if (statements.Legislations.Count > 0)
            {
                qcAtIssuance = false;
                notes.Add($"Qualified under another legislation ({string.Join(", ", statements.Legislations)}), not the EU's.");
            }

            type = Has(qualifiers, "QCForESig") ? "esig" : Has(qualifiers, "QCForESeal") ? "eseal" : Has(qualifiers, "QCForWSA") ? "wsa" : type;
            notes.Add(qcAtIssuance ? $"Qualified certificate at issuance, for {Describe(type)}." : "Not a qualified certificate (no QcCompliance).");
        }

        // At the signing time: the service still granted, and whether the key is on a QSCD.
        bool qualified = qcAtIssuance;
        bool qscd = false;
        var atSigning = service.InformationAt(signingTime);
        if (qcAtIssuance && (atSigning is null || !IsActive(atSigning.Status)))
        {
            qualified = false;
            notes.Add($"At the signing time ({signingTime:yyyy-MM-dd HH:mm} UTC) the CA/QC service was not granted: no longer qualified.");
        }
        else if (qcAtIssuance)
        {
            var qualifiers = atSigning!.Extensions.QualifiersFor(signer);
            qscd = statements.QcSscd;
            if (Has(qualifiers, "QCWithQSCD") || Has(qualifiers, "QCWithSSCD") || Has(qualifiers, "QCQSCDManagedOnBehalf"))
            {
                qscd = true;
            }
            else if (Has(qualifiers, "QCNoQSCD") || Has(qualifiers, "QCNoSSCD"))
            {
                qscd = false;
            }

            notes.Add(qscd ? "The key is on a qualified signature/seal creation device." : "The key is not declared on a QSCD.");
        }

        string level = Level(qualified, qscd, type);
        notes.Add(context.Indication switch
        {
            SignatureIndication.Valid => $"Valid signature: {level}.",
            SignatureIndication.Invalid => "The signature failed: not an advanced signature.",
            _ => $"Indeterminate validation: {level} not established.",
        });
        level = context.Indication switch
        {
            SignatureIndication.Valid => level,
            SignatureIndication.Invalid => SignatureQualificationLevels.NotAdES,
            _ => "Indeterminate " + level,
        };
        return Result(level, notes, timestamps);
    }

    private static SignatureQualification Result(string level, List<string> notes, IReadOnlyList<TimestampQualification> timestamps) => new(level)
    {
        EtsiUri = EtsiUriPrefix + level.Replace(' ', '_'),
        Framework = "eIDAS",
        Notes = notes,
        Timestamps = timestamps,
    };

    private static string Level(bool qualified, bool qscd, string type) => (qualified, qscd, type) switch
    {
        (true, true, "eseal") => SignatureQualificationLevels.QESeal,
        (true, true, "esig") => SignatureQualificationLevels.QESig,
        (true, false, "eseal") => SignatureQualificationLevels.AdESealQC,
        (true, false, "esig") => SignatureQualificationLevels.AdESigQC,
        (_, _, "eseal") => SignatureQualificationLevels.AdESeal,
        _ => SignatureQualificationLevels.AdESig,
    };

    /// <summary>The certificate's use: its QcType, else the service's AdditionalServiceInformation, else signatures (the eIDAS default).</summary>
    private static string TypeOf(QcStatements statements, TrustedListServiceExtensions extensions)
    {
        if (statements.Types.Contains(QcStatements.ESealOid))
        {
            return "eseal";
        }

        if (statements.Types.Contains(QcStatements.ESignOid))
        {
            return "esig";
        }

        if (statements.Types.Contains(QcStatements.WebOid))
        {
            return "wsa";
        }

        bool signatures = extensions.HasAdditionalInformation("/ForeSignatures");
        bool seals = extensions.HasAdditionalInformation("/ForeSeals");
        return seals && !signatures ? "eseal" : "esig";
    }

    private static string Describe(string type) => type switch
    {
        "eseal" => "electronic seals",
        "wsa" => "website authentication",
        _ => "electronic signatures",
    };

    /// <summary>The CA/QC or CA/PKC service the signer's chain reaches, walking up by issuer name through the signature's certificates.</summary>
    private static TrustedListService? CaService(X509Certificate2 signer, IReadOnlyList<X509Certificate2> certificates, IReadOnlyList<TrustedList> lists)
    {
        var services = lists.SelectMany(l => l.Services)
            .Where(s => s.ServiceType.EndsWith("/CA/QC", StringComparison.OrdinalIgnoreCase) || s.ServiceType.EndsWith("/CA/PKC", StringComparison.OrdinalIgnoreCase))
            .ToList();
        var current = signer;
        for (int depth = 0; depth < 10; depth++)
        {
            var issuer = current.IssuerName.RawData;
            var service = services.FirstOrDefault(s => s.Certificates.Any(c => c.SubjectName.RawData.AsSpan().SequenceEqual(issuer) && Issued(c, current)));
            if (service is not null)
            {
                return service;
            }

            var parent = certificates.FirstOrDefault(c => c.SubjectName.RawData.AsSpan().SequenceEqual(issuer)
                && !c.RawData.AsSpan().SequenceEqual(current.RawData) && Issued(c, current));
            if (parent is null || parent.SubjectName.RawData.AsSpan().SequenceEqual(parent.IssuerName.RawData))
            {
                return null;
            }

            current = parent;
        }

        return null;
    }

    /// <summary>
    /// Whether <paramref name="issuer"/> issued <paramref name="certificate"/>: same name (checked by the caller), and the
    /// certificate's authority key identifier is the issuer's subject key identifier when both are there. The validation
    /// already checked the signatures of the chain.
    /// </summary>
    private static bool Issued(X509Certificate2 issuer, X509Certificate2 certificate)
    {
        var authority = certificate.Extensions.OfType<X509AuthorityKeyIdentifierExtension>().FirstOrDefault()?.KeyIdentifier;
        var subject = issuer.Extensions.OfType<X509SubjectKeyIdentifierExtension>().FirstOrDefault()?.SubjectKeyIdentifierBytes;
        return authority is not { } a || subject is not { } b || a.Span.SequenceEqual(b.Span);
    }

    /// <summary>Each timestamp: QTSA when a TSA/QTST service of the lists, granted at its time, is its TSA; TSA when another TSA service is; N/A otherwise.</summary>
    private static List<TimestampQualification> Timestamps(SignatureQualificationContext context, IReadOnlyList<TrustedList> lists)
    {
        var result = new List<TimestampQualification>();
        var tsaServices = lists.SelectMany(l => l.Services)
            .Where(s => s.ServiceType.Contains("/TSA", StringComparison.OrdinalIgnoreCase)).ToList();
        foreach (var entry in context.ValidationObjects.Where(o => o.Type == ValidationObjectType.Timestamp && o.Time is not null))
        {
            X509Certificate2? tsa = null;
            try
            {
                var cms = new SignedCms();
                cms.Decode(entry.Data.Span);
                tsa = cms.SignerInfos.Count > 0 ? cms.SignerInfos[0].Certificate : null;
            }
            catch (CryptographicException)
            {
                // An unreadable token has no known TSA.
            }

            var time = entry.Time!.Value;
            string level = "N/A";
            if (tsa is not null && tsaServices.FirstOrDefault(s => s.Certificates.Any(c => c.RawData.AsSpan().SequenceEqual(tsa.RawData))) is { } service)
            {
                bool active = service.InformationAt(time) is { } then && IsActive(then.Status);
                level = active && service.ServiceType.EndsWith("/TSA/QTST", StringComparison.OrdinalIgnoreCase) ? "QTSA" : "TSA";
            }

            result.Add(new TimestampQualification(time, level) { Tsa = tsa?.GetNameInfo(X509NameType.SimpleName, forIssuer: false) });
        }

        return result;
    }

    private static bool Has(IReadOnlyList<string> qualifiers, string name) =>
        qualifiers.Any(q => string.Equals(q, QualifierPrefix + name, StringComparison.OrdinalIgnoreCase) || q.EndsWith("/" + name, StringComparison.OrdinalIgnoreCase));

    private static bool IsActive(string status) => ActiveStatuses.Any(s => status.EndsWith(s, StringComparison.OrdinalIgnoreCase));

    private static bool IsCaQc(string serviceType) => serviceType.EndsWith("/CA/QC", StringComparison.OrdinalIgnoreCase);

    private static string Last(string uri) => uri[(uri.LastIndexOf("Svctype/", StringComparison.Ordinal) is int i and >= 0 ? i + 8 : 0)..];
}
