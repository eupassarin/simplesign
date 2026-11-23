using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Constants;

namespace SimpleSign.Core.Extensions;

/// <summary>
/// Reads the identifiers any X.509 certificate may carry: its holder's email addresses
/// (<see cref="SignerIdentifierTypes.Email"/>: SubjectAltName rfc822Name, then the subject's emailAddress), the subject's
/// serialNumber (<see cref="SignerIdentifierTypes.SerialNumber"/>) and organizationIdentifier
/// (<see cref="SignerIdentifierTypes.OrganizationIdentifier"/>), the identifiers of a natural or legal person written as
/// ETSI EN 319 412-1 defines them (<see cref="SignerIdentifierTypes.NaturalPersonId"/>,
/// <see cref="SignerIdentifierTypes.LegalPersonId"/>: European qualified certificates and others that follow it) and the
/// SHA-256 digest of the certificate (<see cref="SignerIdentifierTypes.CertificateSha256"/>). Identifiers a framework
/// places elsewhere come from the readers of a country extension (<see cref="ICountryExtension.SignerIdentityReaders"/>:
/// the Brazilian CPF and CNPJ, in SubjectAltName otherNames).
/// </summary>
public sealed class DefaultSignerIdentityReader : ISignerIdentityReader
{
    private const string EmailAddressOid = "1.2.840.113549.1.9.1";
    private const string SerialNumberOid = "2.5.4.5";
    private const string OrganizationIdentifierOid = "2.5.4.97";

    /// <summary>The types of identity of a natural person (ETSI EN 319 412-1 §5.1.3); TAX is the earlier name of TIN.</summary>
    private static readonly string[] s_naturalPersonTypes = ["PAS", "IDC", "PNO", "TAX", "TIN"];

    /// <summary>The types of identifier of a legal person (ETSI EN 319 412-1 §5.1.4).</summary>
    private static readonly string[] s_legalPersonTypes = ["VAT", "NTR", "PSD", "LEI"];

    /// <summary>The shared instance; the reader keeps no state.</summary>
    public static DefaultSignerIdentityReader Instance { get; } = new();

    /// <inheritdoc />
    public IReadOnlyCollection<string> IdentifierTypes { get; } =
    [
        SignerIdentifierTypes.Email, SignerIdentifierTypes.SerialNumber, SignerIdentifierTypes.OrganizationIdentifier,
        SignerIdentifierTypes.NaturalPersonId, SignerIdentifierTypes.LegalPersonId, SignerIdentifierTypes.CertificateSha256,
    ];

    /// <inheritdoc />
    public IReadOnlyList<string> Read(X509Certificate2 certificate, string identifierType)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(identifierType);
        IEnumerable<string> values = identifierType.ToUpperInvariant() switch
        {
            SignerIdentifierTypes.Email => SanEmails(certificate).Concat(SubjectValues(certificate, EmailAddressOid)),
            SignerIdentifierTypes.SerialNumber => SubjectValues(certificate, SerialNumberOid),
            SignerIdentifierTypes.OrganizationIdentifier => SubjectValues(certificate, OrganizationIdentifierOid),
            SignerIdentifierTypes.NaturalPersonId =>
                SubjectValues(certificate, SerialNumberOid).Select(v => SemanticsIdentifier(v, s_naturalPersonTypes)).OfType<string>(),
            SignerIdentifierTypes.LegalPersonId =>
                SubjectValues(certificate, OrganizationIdentifierOid).Select(v => SemanticsIdentifier(v, s_legalPersonTypes)).OfType<string>(),
            SignerIdentifierTypes.CertificateSha256 => [Convert.ToHexString(SHA256.HashData(certificate.RawData))],
            _ => [],
        };
        return [.. values.Select(v => v.Trim()).Where(v => v.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase)];
    }

    /// <summary>
    /// <paramref name="value"/> when it is written as ETSI EN 319 412-1 §5.1.3/§5.1.4 defines: a type of
    /// <paramref name="types"/> or a national scheme (two letters and a colon), two letters of country, a hyphen and a
    /// non-empty identifier. The type and country in upper case; null when the value has another form.
    /// </summary>
    private static string? SemanticsIdentifier(string value, string[] types)
    {
        string trimmed = value.Trim();
        int hyphen = trimmed.IndexOf('-', StringComparison.Ordinal);
        if (hyphen != 5 || hyphen == trimmed.Length - 1)
        {
            return null;
        }

        string prefix = trimmed[..5].ToUpperInvariant();
        bool national = prefix[2] == ':' && char.IsAsciiLetter(prefix[0]) && char.IsAsciiLetter(prefix[1]);
        bool known = types.Contains(prefix[..3], StringComparer.Ordinal);
        return (national || known) && char.IsAsciiLetter(prefix[3]) && char.IsAsciiLetter(prefix[4])
            ? prefix + trimmed[5..]
            : null;
    }

    /// <summary>The rfc822Name entries (<c>[1] IA5String</c>) of the SubjectAltName extension; none when it cannot be read.</summary>
    private static List<string> SanEmails(X509Certificate2 certificate)
    {
        var emails = new List<string>();
        if (certificate.Extensions[Oids.SubjectAltName] is not { } extension)
        {
            return emails;
        }

        var rfc822Name = new Asn1Tag(TagClass.ContextSpecific, 1);
        try
        {
            var names = new AsnReader(extension.RawData, AsnEncodingRules.DER).ReadSequence();
            while (names.HasData)
            {
                if (names.PeekTag().HasSameClassAndValue(rfc822Name))
                {
                    emails.Add(names.ReadCharacterString(UniversalTagNumber.IA5String, rfc822Name));
                }
                else
                {
                    _ = names.ReadEncodedValue();
                }
            }
        }
        catch (AsnContentException)
        {
            // A malformed SubjectAltName: the names read before stand.
        }

        return emails;
    }

    /// <summary>The values of the subject's attributes of type <paramref name="oid"/>, in the order of the name.</summary>
    private static IEnumerable<string> SubjectValues(X509Certificate2 certificate, string oid) =>
        certificate.SubjectName.EnumerateRelativeDistinguishedNames()
            .Where(rdn => !rdn.HasMultipleElements && rdn.GetSingleElementType().Value == oid)
            .Select(rdn => rdn.GetSingleElementValue())
            .OfType<string>();
}
