namespace SimpleSign.Brazil.Internal;

/// <summary>Check-digit validation of CPF and CNPJ numbers (digits only, no formatting).</summary>
internal static class BrazilDocuments
{
    /// <summary>
    /// Validates a CPF number using the mod-11 check digit algorithm.
    /// </summary>
    internal static bool IsValidCpf(string cpf)
    {
        if (cpf.Length != 11 || !cpf.All(char.IsDigit))
        {
            return false;
        }

        // Reject sequences of identical digits (e.g., 111.111.111-11)
        if (cpf.Distinct().Count() == 1)
        {
            return false;
        }

        // First check digit
        int sum = 0;
        for (int i = 0; i < 9; i++)
        {
            sum += (cpf[i] - '0') * (10 - i);
        }
        int remainder = sum % 11;
        int digit1 = remainder < 2 ? 0 : 11 - remainder;
        if (cpf[9] - '0' != digit1)
        {
            return false;
        }

        // Second check digit
        sum = 0;
        for (int i = 0; i < 10; i++)
        {
            sum += (cpf[i] - '0') * (11 - i);
        }
        remainder = sum % 11;
        int digit2 = remainder < 2 ? 0 : 11 - remainder;
        return cpf[10] - '0' == digit2;
    }

    /// <summary>
    /// Validates a CNPJ with the mod-11 check digits. Accepts the alphanumeric format of
    /// IN RFB 2.229/2024 (in force since July 2026): the first 12 characters are 0–9 or A–Z
    /// (uppercase), each worth its ASCII code minus 48; the last two are numeric check digits.
    /// </summary>
    internal static bool IsValidCnpj(string cnpj)
    {
        if (cnpj.Length != 14
            || cnpj.AsSpan(0, 12).IndexOfAnyExcept(CnpjBaseCharacters) >= 0
            || !char.IsAsciiDigit(cnpj[12]) || !char.IsAsciiDigit(cnpj[13]))
        {
            return false;
        }

        if (cnpj.Distinct().Count() == 1)
        {
            return false;
        }

        // First check digit (weights: 5,4,3,2,9,8,7,6,5,4,3,2)
        int[] weights1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
        int sum = 0;
        for (int i = 0; i < 12; i++)
        {
            sum += (cnpj[i] - '0') * weights1[i];
        }
        int remainder = sum % 11;
        int digit1 = remainder < 2 ? 0 : 11 - remainder;
        if (cnpj[12] - '0' != digit1)
        {
            return false;
        }

        // Second check digit (weights: 6,5,4,3,2,9,8,7,6,5,4,3,2)
        int[] weights2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
        sum = 0;
        for (int i = 0; i < 13; i++)
        {
            sum += (cnpj[i] - '0') * weights2[i];
        }
        remainder = sum % 11;
        int digit2 = remainder < 2 ? 0 : 11 - remainder;
        return cnpj[13] - '0' == digit2;
    }

    private static readonly System.Buffers.SearchValues<char> CnpjBaseCharacters =
        System.Buffers.SearchValues.Create("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ");
}
