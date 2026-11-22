using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Core.Extensions;

/// <summary>
/// Reads from a certificate the identifiers of its holder of a given type: a national number (the CPF or CNPJ of a
/// Brazilian certificate), an email address, the subject's serial number, the certificate's own digest. It lets a
/// caller check that a certificate is that of an expected signer (a signature envelope names its signers by such
/// identifiers). A country extension gives its readers in <see cref="ICountryExtension.SignerIdentityReaders"/>;
/// <see cref="DefaultSignerIdentityReader"/> reads the identifiers any X.509 certificate may carry.
/// </summary>
public interface ISignerIdentityReader
{
    /// <summary>The identifier types this reader knows (see <see cref="SignerIdentifierTypes"/>), in upper case.</summary>
    IReadOnlyCollection<string> IdentifierTypes { get; }

    /// <summary>
    /// The identifiers of type <paramref name="identifierType"/> that <paramref name="certificate"/> carries, normalized as
    /// the type says (<see cref="SignerIdentifierTypes"/>). Empty when the certificate has none, or when the reader does not
    /// know the type (compared without regard to case).
    /// </summary>
    /// <param name="certificate">The certificate to read.</param>
    /// <param name="identifierType">The identifier type, for example <see cref="SignerIdentifierTypes.Cpf"/>.</param>
    /// <returns>The identifiers, without duplicates; empty when there are none.</returns>
    IReadOnlyList<string> Read(X509Certificate2 certificate, string identifierType);
}

/// <summary>The identifier types the readers of SimpleSign know (<see cref="ISignerIdentityReader"/>).</summary>
public static class SignerIdentifierTypes
{
    /// <summary>The Brazilian CPF of a natural person: its 11 digits, no punctuation.</summary>
    public const string Cpf = "CPF";

    /// <summary>
    /// The Brazilian CPF of the natural person responsible for a legal entity's certificate (an ICP-Brasil e-CNPJ):
    /// its 11 digits. Not <see cref="Cpf"/>: the certificate is issued to the company, and this person holds it for the
    /// company. A signer listed by CPF who signs for a company is matched by this type, not by <see cref="Cpf"/>.
    /// </summary>
    public const string ResponsibleCpf = "RESPONSIBLE-CPF";

    /// <summary>The Brazilian CNPJ of a legal entity: its 14 characters (digits, or upper-case letters in the alphanumeric format), no punctuation.</summary>
    public const string Cnpj = "CNPJ";

    /// <summary>An email address of the holder (SubjectAltName rfc822Name, or the subject's emailAddress), trimmed, as written.</summary>
    public const string Email = "EMAIL";

    /// <summary>The subject's serialNumber attribute (X.520, OID 2.5.4.5), trimmed, as written: often a national identifier with its prefix (ETSI EN 319 412-1 §5.1.3).</summary>
    public const string SerialNumber = "SERIALNUMBER";

    /// <summary>
    /// The identifier of a natural person in the form of ETSI EN 319 412-1 §5.1.3, read from the subject's serialNumber:
    /// the type of identity (PAS passport, IDC identity card, PNO personal number, TIN or TAX tax number, or a national
    /// scheme written as two letters and a colon), the ISO 3166 country, a hyphen and the identifier — for example
    /// <c>PNOBE-85010112345</c>. The type and country are returned in upper case, the identifier as written. Used by
    /// European qualified certificates (ETSI EN 319 412-2) and by other authorities that follow the standard.
    /// </summary>
    public const string NaturalPersonId = "NATURAL-PERSON-ID";

    /// <summary>
    /// The identifier of a legal person in the form of ETSI EN 319 412-1 §5.1.4, read from the subject's
    /// organizationIdentifier: the type (VAT, NTR national trade register, PSD payment service provider, LEI legal
    /// entity identifier, or a national scheme written as two letters and a colon), the ISO 3166 country (XG for LEI), a
    /// hyphen and the identifier — for example <c>VATBE-0123456789</c>. The type and country are returned in upper case.
    /// </summary>
    public const string LegalPersonId = "LEGAL-PERSON-ID";

    /// <summary>The subject's organizationIdentifier attribute (X.520, OID 2.5.4.97), trimmed, as written, whatever its form.</summary>
    public const string OrganizationIdentifier = "ORGANIZATIONIDENTIFIER";

    /// <summary>The SHA-256 digest of the certificate (its DER encoding), in upper-case hexadecimal: names one certificate, not a person.</summary>
    public const string CertificateSha256 = "CERT-SHA256";
}
