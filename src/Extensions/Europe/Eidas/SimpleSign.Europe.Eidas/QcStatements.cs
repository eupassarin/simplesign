using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Europe.Eidas;

/// <summary>
/// The QC statements of a certificate (RFC 3739, ETSI EN 319 412-5): whether it claims to be an EU qualified
/// certificate, for which use, with its key on a QSCD, and under which legislation.
/// </summary>
public sealed record QcStatements
{
    /// <summary>The OID of the QcStatements extension.</summary>
    public const string ExtensionOid = "1.3.6.1.5.5.7.1.3";

    /// <summary>QcCompliance: an EU qualified certificate (0.4.0.1862.1.1).</summary>
    public const string QcComplianceOid = "0.4.0.1862.1.1";

    /// <summary>QcSSCD: the private key is on a qualified signature/seal creation device (0.4.0.1862.1.4).</summary>
    public const string QcSscdOid = "0.4.0.1862.1.4";

    /// <summary>QcPDS: the PKI disclosure statements (0.4.0.1862.1.5).</summary>
    public const string QcPdsOid = "0.4.0.1862.1.5";

    /// <summary>QcType: what the certificate is for (0.4.0.1862.1.6).</summary>
    public const string QcTypeOid = "0.4.0.1862.1.6";

    /// <summary>QcCClegislation: the non-EU legislations it is qualified under (0.4.0.1862.1.7).</summary>
    public const string QcCcLegislationOid = "0.4.0.1862.1.7";

    /// <summary>QcType esign: for electronic signatures (0.4.0.1862.1.6.1).</summary>
    public const string ESignOid = "0.4.0.1862.1.6.1";

    /// <summary>QcType eseal: for electronic seals (0.4.0.1862.1.6.2).</summary>
    public const string ESealOid = "0.4.0.1862.1.6.2";

    /// <summary>QcType web: for website authentication (0.4.0.1862.1.6.3).</summary>
    public const string WebOid = "0.4.0.1862.1.6.3";

    /// <summary>No QC statement.</summary>
    public static QcStatements None { get; } = new();

    /// <summary>Whether the certificate has the extension at all.</summary>
    public bool Present { get; init; }

    /// <summary>The statement OIDs, in order.</summary>
    public IReadOnlyList<string> Statements { get; init; } = [];

    /// <summary>Whether it has QcCompliance.</summary>
    public bool QcCompliance => Statements.Contains(QcComplianceOid);

    /// <summary>Whether it has QcSSCD.</summary>
    public bool QcSscd => Statements.Contains(QcSscdOid);

    /// <summary>The QcType OIDs (<see cref="ESignOid"/>, <see cref="ESealOid"/>, <see cref="WebOid"/>); empty when absent.</summary>
    public IReadOnlyList<string> Types { get; init; } = [];

    /// <summary>The QcCClegislation country codes; empty for an EU qualified certificate.</summary>
    public IReadOnlyList<string> Legislations { get; init; } = [];

    /// <summary>The QcPDS locations (URLs).</summary>
    public IReadOnlyList<string> PdsLocations { get; init; } = [];

    /// <summary>Reads the QC statements of <paramref name="certificate"/>.</summary>
    /// <param name="certificate">The certificate.</param>
    /// <returns>Its QC statements; <see cref="None"/> without the extension or when it is malformed.</returns>
    public static QcStatements Decode(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        if (certificate.Extensions[ExtensionOid] is not { } extension)
        {
            return None;
        }

        var statements = new List<string>();
        var types = new List<string>();
        var legislations = new List<string>();
        var pds = new List<string>();
        try
        {
            var reader = new AsnReader(extension.RawData, AsnEncodingRules.DER).ReadSequence();
            while (reader.HasData)
            {
                var statement = reader.ReadSequence();
                string id = statement.ReadObjectIdentifier();
                statements.Add(id);
                if (!statement.HasData)
                {
                    continue;
                }

                switch (id)
                {
                    case QcTypeOid:
                        var typeList = statement.ReadSequence();
                        while (typeList.HasData)
                        {
                            types.Add(typeList.ReadObjectIdentifier());
                        }

                        break;
                    case QcCcLegislationOid:
                        var countries = statement.ReadSequence();
                        while (countries.HasData)
                        {
                            legislations.Add(countries.ReadCharacterString(UniversalTagNumber.PrintableString));
                        }

                        break;
                    case QcPdsOid:
                        var locations = statement.ReadSequence();
                        while (locations.HasData)
                        {
                            var location = locations.ReadSequence();
                            pds.Add(location.ReadCharacterString(UniversalTagNumber.IA5String));
                        }

                        break;
                    default:
                        break;
                }
            }
        }
        catch (AsnContentException)
        {
            return new QcStatements { Present = true, Statements = statements };
        }

        return new QcStatements { Present = true, Statements = statements, Types = types, Legislations = legislations, PdsLocations = pds };
    }

    /// <summary>The DER of a QcStatements extension value, for tests and the Sandbox.</summary>
    /// <param name="compliance">Whether to add QcCompliance.</param>
    /// <param name="sscd">Whether to add QcSSCD.</param>
    /// <param name="types">The QcType OIDs; none to leave QcType out.</param>
    /// <returns>The extension value.</returns>
    public static byte[] Encode(bool compliance, bool sscd, params string[] types)
    {
        ArgumentNullException.ThrowIfNull(types);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            if (compliance)
            {
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(QcComplianceOid);
                }
            }

            if (sscd)
            {
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(QcSscdOid);
                }
            }

            if (types.Length > 0)
            {
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(QcTypeOid);
                    using (writer.PushSequence())
                    {
                        foreach (string type in types)
                        {
                            writer.WriteObjectIdentifier(type);
                        }
                    }
                }
            }
        }

        return writer.Encode();
    }
}
