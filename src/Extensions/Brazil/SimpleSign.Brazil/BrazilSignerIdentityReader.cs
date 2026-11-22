using System.Security.Cryptography.X509Certificates;
using SimpleSign.Brazil.Internal;
using SimpleSign.Core.Extensions;

namespace SimpleSign.Brazil;

/// <summary>
/// Reads the CPF and CNPJ of ICP-Brasil and Gov.br certificates (DOC-ICP-04), from the SubjectAltName otherNames:
/// <see cref="SignerIdentifierTypes.Cpf"/> from the holder data of a natural person (2.16.76.1.3.1: birth date then
/// CPF, or the CPF alone in Gov.br certificates), <see cref="SignerIdentifierTypes.Cnpj"/> from the CNPJ of a legal
/// entity (2.16.76.1.3.3) and <see cref="SignerIdentifierTypes.ResponsibleCpf"/> from the data of the person responsible
/// for an e-CNPJ (2.16.76.1.3.4: birth date then CPF). The responsible person's CPF is a type of its own, not
/// <see cref="SignerIdentifierTypes.Cpf"/>: the certificate is the company's, and that person holds it for the company.
/// Only identifiers with valid check digits are returned. The ICP-Brasil and Gov.br country extensions return it in
/// <see cref="ICountryExtension.SignerIdentityReaders"/>.
/// </summary>
public sealed class BrazilSignerIdentityReader : ISignerIdentityReader
{
    /// <summary>The shared instance; the reader keeps no state.</summary>
    public static BrazilSignerIdentityReader Instance { get; } = new();

    /// <inheritdoc />
    public IReadOnlyCollection<string> IdentifierTypes { get; } =
        [SignerIdentifierTypes.Cpf, SignerIdentifierTypes.Cnpj, SignerIdentifierTypes.ResponsibleCpf];

    /// <inheritdoc />
    public IReadOnlyList<string> Read(X509Certificate2 certificate, string identifierType)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(identifierType);
        (string Oid, Func<string, string?> Parse)? field = identifierType.ToUpperInvariant() switch
        {
            SignerIdentifierTypes.Cpf => (BrazilOids.IcpBrasilSanHolderData, Cpf),
            SignerIdentifierTypes.Cnpj => (BrazilOids.IcpBrasilSanCnpj, Cnpj),
            SignerIdentifierTypes.ResponsibleCpf => (BrazilOids.IcpBrasilSanResponsibleData, v => BrazilSan.CpfFromHolderData(v.Trim())),
            _ => null,
        };
        if (field is not { } f)
        {
            return [];
        }

        return [.. BrazilSan.ReadOtherNames(certificate, logger: null)
            .Where(n => n.Oid == f.Oid)
            .Select(n => f.Parse(n.Value))
            .OfType<string>()
            .Distinct(StringComparer.Ordinal)];
    }

    /// <summary>The CPF of a holder-data field: the CPF alone (Gov.br), or birth date then CPF (ICP-Brasil).</summary>
    private static string? Cpf(string value)
    {
        string trimmed = value.Trim();
        return trimmed.Length == 11 && BrazilDocuments.IsValidCpf(trimmed) ? trimmed : BrazilSan.CpfFromHolderData(trimmed);
    }

    /// <summary>The CNPJ of a CNPJ field: its first 14 characters, in upper case (alphanumeric CNPJ).</summary>
    private static string? Cnpj(string value)
    {
        string trimmed = value.Trim();
        if (trimmed.Length < 14)
        {
            return null;
        }

        string cnpj = trimmed[..14].ToUpperInvariant();
        return BrazilDocuments.IsValidCnpj(cnpj) ? cnpj : null;
    }
}
