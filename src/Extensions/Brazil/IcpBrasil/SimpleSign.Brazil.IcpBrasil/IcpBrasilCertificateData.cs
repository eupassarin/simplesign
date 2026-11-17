using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using SimpleSign.Brazil.Internal;

namespace SimpleSign.Brazil.IcpBrasil;

/// <summary>Whether an ICP-Brasil certificate belongs to a person or to a legal entity.</summary>
public enum IcpBrasilHolderType
{
    /// <summary>Neither the PF (2.16.76.1.3.1) nor the PJ (2.16.76.1.3.3) fields are present.</summary>
    Unknown,

    /// <summary>e-CPF and other PF certificates (holder data 2.16.76.1.3.1).</summary>
    PessoaFisica,

    /// <summary>e-CNPJ and other PJ certificates (CNPJ 2.16.76.1.3.3).</summary>
    PessoaJuridica,
}

/// <summary>
/// Personal data in the ICP-Brasil layout of 2.16.76.1.3.1 (holder) and 2.16.76.1.3.4 (person
/// responsible for a PJ): birth date (8), CPF (11), NIS (11), RG (15), RG issuer and UF (6).
/// Fields filled with zeros in the certificate are <see langword="null"/>.
/// </summary>
/// <param name="BirthDate">Date of birth.</param>
/// <param name="Cpf">CPF, 11 digits.</param>
/// <param name="Nis">NIS (PIS/PASEP/NIT), 11 digits.</param>
/// <param name="Rg">RG number, without leading zeros.</param>
/// <param name="RgIssuer">RG issuer and UF (e.g. "SSPSP").</param>
public sealed record IcpBrasilPersonData(DateOnly? BirthDate, string? Cpf, string? Nis, string? Rg, string? RgIssuer);

/// <summary>Voter registration (título de eleitor) from 2.16.76.1.3.5.</summary>
/// <param name="Number">Registration number (12).</param>
/// <param name="Zone">Electoral zone (3).</param>
/// <param name="Section">Electoral section (4).</param>
/// <param name="MunicipalityAndState">Municipality and UF (22).</param>
public sealed record IcpBrasilVoterRegistration(string Number, string? Zone, string? Section, string? MunicipalityAndState);

/// <summary>
/// The holder data an ICP-Brasil certificate carries in its SubjectAltName otherNames
/// (DOC-ICP-04, item 7.1.2.3): PF fields 2.16.76.1.3.1/.5/.6, PJ fields 2.16.76.1.3.2/.3/.4/.7/.8,
/// and the professional registrations under 2.16.76.1.4.2.
/// </summary>
public sealed class IcpBrasilCertificateData
{
    /// <summary>PF or PJ.</summary>
    public IcpBrasilHolderType HolderType { get; init; }

    /// <summary>Holder data of a PF certificate (2.16.76.1.3.1).</summary>
    public IcpBrasilPersonData? Holder { get; init; }

    /// <summary>Voter registration of a PF certificate (2.16.76.1.3.5).</summary>
    public IcpBrasilVoterRegistration? VoterRegistration { get; init; }

    /// <summary>CEI/CAEPF of the PF (2.16.76.1.3.6) or CEI of the PJ (2.16.76.1.3.7), 12 digits.</summary>
    public string? Cei { get; init; }

    /// <summary>CNPJ of a PJ certificate (2.16.76.1.3.3), possibly alphanumeric.</summary>
    public string? Cnpj { get; init; }

    /// <summary>Name of the person responsible for a PJ certificate (2.16.76.1.3.2).</summary>
    public string? ResponsibleName { get; init; }

    /// <summary>Data of the person responsible for a PJ certificate (2.16.76.1.3.4), including the CPF.</summary>
    public IcpBrasilPersonData? Responsible { get; init; }

    /// <summary>Company name (nome empresarial) of a PJ certificate (2.16.76.1.3.8).</summary>
    public string? CompanyName { get; init; }

    /// <summary>Professional registrations (OAB, CFM, CFF…) under 2.16.76.1.4.2.</summary>
    public IReadOnlyList<ProfessionalRegistration> ProfessionalRegistrations { get; init; } = [];

    /// <summary>The CPF that identifies the signer: the holder's (PF) or the responsible person's (PJ).</summary>
    public string? SignerCpf => Holder?.Cpf ?? Responsible?.Cpf;

    /// <summary>Reads the ICP-Brasil holder data from <paramref name="certificate"/>.</summary>
    /// <param name="certificate">An ICP-Brasil certificate.</param>
    /// <param name="logger">Optional logger for malformed SubjectAltName extensions.</param>
    /// <exception cref="ArgumentNullException"><paramref name="certificate"/> is null.</exception>
    public static IcpBrasilCertificateData FromCertificate(X509Certificate2 certificate, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        var names = BrazilSan.ReadOtherNames(certificate, logger);
        string? Get(string oid) => names.FirstOrDefault(n => n.Oid == oid).Value;

        var holder = ParsePerson(Get("2.16.76.1.3.1"));
        string? cnpjRaw = Get("2.16.76.1.3.3");
        string? cnpj = cnpjRaw is { Length: >= 14 } && BrazilDocuments.IsValidCnpj(cnpjRaw[..14].ToUpperInvariant())
            ? cnpjRaw[..14].ToUpperInvariant()
            : null;

        return new IcpBrasilCertificateData
        {
            HolderType = cnpjRaw is not null ? IcpBrasilHolderType.PessoaJuridica
                : holder is not null ? IcpBrasilHolderType.PessoaFisica
                : IcpBrasilHolderType.Unknown,
            Holder = holder,
            VoterRegistration = ParseVoter(Get("2.16.76.1.3.5")),
            Cei = NonZero(Get("2.16.76.1.3.6")) ?? NonZero(Get("2.16.76.1.3.7")),
            Cnpj = cnpj,
            ResponsibleName = Text(Get("2.16.76.1.3.2")),
            Responsible = ParsePerson(Get("2.16.76.1.3.4")),
            CompanyName = Text(Get("2.16.76.1.3.8")),
            ProfessionalRegistrations = IcpBrasilChainValidator.ExtractProfessionalRegistrations(certificate, logger),
        };
    }

    internal static IcpBrasilPersonData? ParsePerson(string? value)
    {
        if (value is null || value.Length < 19)
        {
            return null;
        }

        string birth = value[..8];
        DateOnly? birthDate = DateOnly.TryParseExact(birth, "ddMMyyyy", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d)
            ? d
            : null;
        string? cpf = BrazilSan.CpfFromHolderData(value);
        string? nis = value.Length >= 30 ? NonZero(value.Substring(19, 11)) : null;
        string? rg = value.Length >= 45 ? NonZero(value.Substring(30, 15))?.TrimStart('0') : null;
        string? issuer = value.Length > 45 ? NonZero(value[45..Math.Min(value.Length, 51)]) : null;
        return new IcpBrasilPersonData(birthDate, cpf, nis, rg, issuer);
    }

    private static IcpBrasilVoterRegistration? ParseVoter(string? value)
    {
        string? number = value is { Length: >= 12 } ? NonZero(value[..12]) : null;
        if (number is null)
        {
            return null;
        }

        return new IcpBrasilVoterRegistration(
            number,
            value!.Length >= 15 ? NonZero(value.Substring(12, 3)) : null,
            value.Length >= 19 ? NonZero(value.Substring(15, 4)) : null,
            value.Length > 19 ? Text(value[19..]) : null);
    }

    /// <summary>Null when the field is empty or zero-filled (the ICP-Brasil "not informed").</summary>
    private static string? NonZero(string? field)
    {
        string? trimmed = field?.Trim();
        return string.IsNullOrEmpty(trimmed) || trimmed.All(c => c == '0') ? null : trimmed;
    }

    private static string? Text(string? field) => string.IsNullOrWhiteSpace(field) ? null : field.Trim();
}
