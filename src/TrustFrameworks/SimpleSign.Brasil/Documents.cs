using SimpleSign.Brasil.IcpBrasil;
using SimpleSign.Brasil.Signing;

namespace SimpleSign.Brasil;

/// <summary>CPF (Cadastro de Pessoas Físicas) validation and formatting.</summary>
public static class Cpf
{
    /// <summary>The 11 digits of <paramref name="cpf"/> without punctuation ("123.456.789-09" → "12345678909").</summary>
    /// <param name="cpf">A CPF, formatted or not.</param>
    /// <returns>The digits, or <see langword="null"/> when the input has other characters or not 11 digits.</returns>
    public static string? Normalize(string? cpf)
    {
        if (cpf is null)
        {
            return null;
        }

        string digits = new([.. cpf.Where(c => c is not ('.' or '-' or ' '))]);
        return digits.Length == 11 && digits.All(char.IsAsciiDigit) ? digits : null;
    }

    /// <summary>Whether <paramref name="cpf"/> (formatted or not) has valid check digits.</summary>
    /// <param name="cpf">A CPF, formatted or not.</param>
    public static bool IsValid(string? cpf) => Normalize(cpf) is { } digits && IcpBrasilChainValidator.IsValidCpf(digits);

    /// <summary>Formats a CPF as 123.456.789-09.</summary>
    /// <param name="cpf">A CPF, formatted or not.</param>
    /// <exception cref="ArgumentException">The CPF does not have 11 digits.</exception>
    public static string Format(string cpf)
    {
        string d = Normalize(cpf) ?? throw new ArgumentException("CPF must contain exactly 11 digits.", nameof(cpf));
        return $"{d[..3]}.{d[3..6]}.{d[6..9]}-{d[9..]}";
    }

    /// <summary>Masks a CPF for display, keeping the six central digits: ***.456.789-**.</summary>
    /// <param name="cpf">A CPF, formatted or not.</param>
    /// <exception cref="ArgumentException">The CPF does not have 11 digits.</exception>
    public static string Mask(string cpf) => AdvancedSignatureInfo.MaskCpf(cpf);
}

/// <summary>
/// CNPJ (Cadastro Nacional da Pessoa Jurídica) validation and formatting, numeric and alphanumeric
/// (IN RFB 2.229/2024: the first 12 characters may be letters).
/// </summary>
public static class Cnpj
{
    /// <summary>The 14 characters of <paramref name="cnpj"/>, uppercase, without punctuation ("12.ABC.345/01DE-35" → "12ABC34501DE35").</summary>
    /// <param name="cnpj">A CNPJ, formatted or not.</param>
    /// <returns>The characters, or <see langword="null"/> when the input is not 14 letters/digits.</returns>
    public static string? Normalize(string? cnpj)
    {
        if (cnpj is null)
        {
            return null;
        }

        string chars = new([.. cnpj.Where(c => c is not ('.' or '-' or '/' or ' ')).Select(char.ToUpperInvariant)]);
        return chars.Length == 14 && chars.All(char.IsAsciiLetterOrDigit) ? chars : null;
    }

    /// <summary>Whether <paramref name="cnpj"/> (formatted or not, numeric or alphanumeric) has valid check digits.</summary>
    /// <param name="cnpj">A CNPJ, formatted or not.</param>
    public static bool IsValid(string? cnpj) => Normalize(cnpj) is { } chars && IcpBrasilChainValidator.IsValidCnpj(chars);

    /// <summary>Formats a CNPJ as 12.345.678/0001-95 (or 12.ABC.345/01DE-35).</summary>
    /// <param name="cnpj">A CNPJ, formatted or not.</param>
    /// <exception cref="ArgumentException">The CNPJ does not have 14 letters/digits.</exception>
    public static string Format(string cnpj)
    {
        string c = Normalize(cnpj) ?? throw new ArgumentException("CNPJ must contain exactly 14 letters or digits.", nameof(cnpj));
        return $"{c[..2]}.{c[2..5]}.{c[5..8]}/{c[8..12]}-{c[12..]}";
    }
}
