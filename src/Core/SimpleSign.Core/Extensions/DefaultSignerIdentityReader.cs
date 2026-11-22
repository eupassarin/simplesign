using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SimpleSign.Core.Constants;

namespace SimpleSign.Core.Extensions;

/// <summary>
/// Reads the identifiers any X.509 certificate may carry: its holder's email addresses
/// (<see cref="SignerIdentifierTypes.Email"/>: SubjectAltName rfc822Name, then the subject's emailAddress), the subject's
/// serialNumber (<see cref="SignerIdentifierTypes.SerialNumber"/>) and the SHA-256 digest of the certificate
/// (<see cref="SignerIdentifierTypes.CertificateSha256"/>). National identifiers come from the readers of a country
/// extension (<see cref="ICountryExtension.SignerIdentityReaders"/>).
/// </summary>
public sealed class DefaultSignerIdentityReader : ISignerIdentityReader
{
    private const string EmailAddressOid = "1.2.840.113549.1.9.1";
    private const string SerialNumberOid = "2.5.4.5";

    /// <summary>The shared instance; the reader keeps no state.</summary>
    public static DefaultSignerIdentityReader Instance { get; } = new();

    /// <inheritdoc />
    public IReadOnlyCollection<string> IdentifierTypes { get; } =
        [SignerIdentifierTypes.Email, SignerIdentifierTypes.SerialNumber, SignerIdentifierTypes.CertificateSha256];

    /// <inheritdoc />
    public IReadOnlyList<string> Read(X509Certificate2 certificate, string identifierType)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(identifierType);
        IEnumerable<string> values = identifierType.ToUpperInvariant() switch
        {
            SignerIdentifierTypes.Email => SanEmails(certificate).Concat(SubjectValues(certificate, EmailAddressOid)),
            SignerIdentifierTypes.SerialNumber => SubjectValues(certificate, SerialNumberOid),
            SignerIdentifierTypes.CertificateSha256 => [Convert.ToHexString(SHA256.HashData(certificate.RawData))],
            _ => [],
        };
        return [.. values.Select(v => v.Trim()).Where(v => v.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase)];
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
