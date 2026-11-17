using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Sandbox.Pki;

/// <summary>One attribute of a subject, as a caller gives it: a short name (<c>CN</c>, <c>serialNumber</c>…) and its value.</summary>
public sealed record SubjectAttribute(string Type, string Value);

/// <summary>
/// The subject of a certificate issued on request: checked against the attributes a signing certificate carries,
/// with X.520 length limits, and built in the order given (most specific first, as a DN string reads).
/// </summary>
internal static class SandboxSubject
{
    /// <summary>The largest number of attributes.</summary>
    public const int MaxAttributes = 16;

    /// <summary>The longest value (X.520 upper bound of most attributes).</summary>
    public const int MaxValueLength = 64;

    /// <summary>The attributes accepted: short name → OID and whether the value is a PrintableString.</summary>
    private static readonly Dictionary<string, (string Oid, bool Printable)> s_types = new(StringComparer.OrdinalIgnoreCase)
    {
        ["CN"] = ("2.5.4.3", false),
        ["SN"] = ("2.5.4.4", false),
        ["surname"] = ("2.5.4.4", false),
        ["serialNumber"] = ("2.5.4.5", true),
        ["C"] = ("2.5.4.6", true),
        ["L"] = ("2.5.4.7", false),
        ["ST"] = ("2.5.4.8", false),
        ["O"] = ("2.5.4.10", false),
        ["OU"] = ("2.5.4.11", false),
        ["T"] = ("2.5.4.12", false),
        ["title"] = ("2.5.4.12", false),
        ["G"] = ("2.5.4.42", false),
        ["GN"] = ("2.5.4.42", false),
        ["givenName"] = ("2.5.4.42", false),
        ["organizationIdentifier"] = ("2.5.4.97", false),
    };

    /// <summary>The short names accepted, for error messages and documentation.</summary>
    public static string Accepted => "CN, serialNumber, C, O, OU, L, ST, T (title), G/GN (givenName), SN (surname), organizationIdentifier";

    /// <summary>
    /// Reads a DN string such as <c>CN=Juan Pérez, serialNumber=PNOPE-12345678, C=PE</c>, most specific first (as
    /// RFC 4514 writes it). Values may be quoted or escape <c>,</c> with a backslash; multi-valued RDNs (<c>+</c>) and
    /// hex values (<c>#…</c>) are not accepted. Parsed here, not by the platform, so the result is the same everywhere.
    /// </summary>
    /// <exception cref="ArgumentException">The string cannot be read or has an attribute that is not accepted.</exception>
    public static X500DistinguishedName Parse(string distinguishedName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);
        if (distinguishedName.Length > MaxAttributes * (MaxValueLength + 32))
        {
            throw new ArgumentException("The subject is too long.");
        }

        var attributes = new List<SubjectAttribute>();
        foreach (string part in SplitRdns(distinguishedName))
        {
            int equals = part.IndexOf('=', StringComparison.Ordinal);
            if (equals <= 0)
            {
                throw new ArgumentException($"'{part.Trim()}' is not a type=value pair.");
            }

            string raw = part[(equals + 1)..].Trim();
            if (raw.StartsWith('#'))
            {
                throw new ArgumentException("Hex-encoded values are not accepted.");
            }

            attributes.Add(new SubjectAttribute(part[..equals].Trim(), Unescape(raw)));
        }

        return Build(attributes);
    }

    /// <summary>
    /// Builds a subject from attributes, most specific first (<c>CN</c> first, <c>C</c> last, as a DN string reads); the
    /// certificate encodes them the other way round (<c>C</c> first), as X.509 does.
    /// </summary>
    /// <exception cref="ArgumentException">An attribute is not accepted, a value is empty or too long, or there is no <c>CN</c>.</exception>
    public static X500DistinguishedName Build(IReadOnlyList<SubjectAttribute> attributes)
    {
        ArgumentNullException.ThrowIfNull(attributes);
        if (attributes.Count is 0 or > MaxAttributes)
        {
            throw new ArgumentException($"Give 1 to {MaxAttributes} subject attributes.");
        }

        var checkedAttributes = new List<(string Oid, bool Printable, string Value)>();
        foreach (var attribute in attributes)
        {
            if (attribute?.Type is null || !s_types.TryGetValue(attribute.Type.Trim(), out var type))
            {
                throw new ArgumentException($"The attribute '{attribute?.Type}' is not accepted; use {Accepted}.");
            }

            string value = attribute.Value?.Trim() ?? "";
            if (value.Length is 0 or > MaxValueLength)
            {
                throw new ArgumentException($"The value of {attribute.Type} must have 1 to {MaxValueLength} characters.");
            }

            if (type.Oid == "2.5.4.6" && (value.Length != 2 || !value.All(char.IsAsciiLetterUpper)))
            {
                throw new ArgumentException("C must be a two-letter country code in upper case (ISO 3166), such as PE or BR.");
            }

            if (type.Printable && !value.All(IsPrintable))
            {
                throw new ArgumentException($"The value of {attribute.Type} may have letters, digits, spaces and ' ( ) + , - . / : = ? only.");
            }

            checkedAttributes.Add((type.Oid, type.Printable, value));
        }

        if (!checkedAttributes.Any(a => a.Oid == "2.5.4.3"))
        {
            throw new ArgumentException("The subject needs a CN.");
        }

        var builder = new X500DistinguishedNameBuilder();
        // The builder puts each attribute before the ones added earlier: adding the most specific first encodes the
        // least specific first, as X.509 does.
        foreach (var (oid, printable, value) in checkedAttributes)
        {
            builder.Add(oid, value, printable ? UniversalTagNumber.PrintableString : UniversalTagNumber.UTF8String);
        }

        return builder.Build();
    }

    /// <summary>Splits a DN string at the commas that are not escaped or quoted.</summary>
    private static List<string> SplitRdns(string distinguishedName)
    {
        var parts = new List<string>();
        var current = new System.Text.StringBuilder();
        bool quoted = false;
        for (int i = 0; i < distinguishedName.Length; i++)
        {
            char c = distinguishedName[i];
            if (c == '\\' && i + 1 < distinguishedName.Length)
            {
                current.Append(c).Append(distinguishedName[++i]);
                continue;
            }

            if (c == '"')
            {
                quoted = !quoted;
            }

            if (c == '+' && !quoted)
            {
                throw new ArgumentException("Multi-valued RDNs are not accepted.");
            }

            if ((c == ',' || c == ';') && !quoted)
            {
                parts.Add(current.ToString());
                current.Clear();
                continue;
            }

            current.Append(c);
        }

        parts.Add(current.ToString());
        return parts;
    }

    /// <summary>Removes the quotes around a value and the backslashes before escaped characters.</summary>
    private static string Unescape(string value)
    {
        if (value.Length >= 2 && value[0] == '"' && value[^1] == '"')
        {
            value = value[1..^1];
        }

        var result = new System.Text.StringBuilder(value.Length);
        for (int i = 0; i < value.Length; i++)
        {
            if (value[i] == '\\' && i + 1 < value.Length)
            {
                i++;
            }

            result.Append(value[i]);
        }

        return result.ToString();
    }

    private static bool IsPrintable(char c) =>
        char.IsAsciiLetterOrDigit(c) || c is ' ' or '\'' or '(' or ')' or '+' or ',' or '-' or '.' or '/' or ':' or '=' or '?';
}
