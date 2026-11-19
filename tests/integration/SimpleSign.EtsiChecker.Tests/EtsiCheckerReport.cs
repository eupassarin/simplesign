using System.Globalization;
using System.Text;
using System.Xml.Linq;

namespace SimpleSign.EtsiChecker.Tests;

/// <summary>How the checker judged one of its checks.</summary>
public enum EtsiCheckOutcome
{
    /// <summary><c>CheckSuccess</c>.</summary>
    Success,

    /// <summary>A warning: an element whose name has <c>Warning</c>.</summary>
    Warning,

    /// <summary><c>CheckFailure</c>, or any other element of a check that is neither a success nor a warning.</summary>
    Failure,
}

/// <summary>One check of the checker that did not succeed.</summary>
/// <param name="Signature">The signature of the file it is about (<c>CAdES-signature-1</c>).</param>
/// <param name="Outcome">Warning or failure.</param>
/// <param name="Element">The element of the report: <c>CheckFailure</c>, <c>CheckWarning</c>…</param>
/// <param name="Check">The checker's test (<c>CheckIfIsCAdESAndBaselineEN319122_1</c>).</param>
/// <param name="Path">Where in the signature: the elements of the report above it, from the root (<c>signedData/signerInfos/signerInfo/signedAttrs</c>).</param>
/// <param name="Message">What the checker says.</param>
public sealed record EtsiFinding(string Signature, EtsiCheckOutcome Outcome, string Element, string Check, string Path, string Message)
{
    /// <inheritdoc/>
    public override string ToString() =>
        $"{Signature} {Element} {Check}{(Path.Length > 0 ? $" at {Path}" : "")}: {Message}";
}

/// <summary>
/// What the ETSI checker says of one file: the <c>xmlrawoutput.xml</c> of each signature in it, read into its
/// failures and warnings. Each check is an element <c>CheckSuccess</c> or <c>CheckFailure</c> (attribute
/// <c>check</c>, text the details), placed under the element of the signature it tests.
/// </summary>
/// <param name="Signatures">The signatures the checker found (<c>siglist</c>), each with its raw report.</param>
/// <param name="Successes">How many checks succeeded.</param>
/// <param name="Findings">The checks that did not.</param>
public sealed record EtsiCheckerReport(IReadOnlyDictionary<string, string> Signatures, int Successes, IReadOnlyList<EtsiFinding> Findings)
{
    /// <summary>The failures.</summary>
    public IEnumerable<EtsiFinding> Failures => Findings.Where(f => f.Outcome == EtsiCheckOutcome.Failure);

    /// <summary>The warnings.</summary>
    public IEnumerable<EtsiFinding> Warnings => Findings.Where(f => f.Outcome == EtsiCheckOutcome.Warning);

    /// <summary>One line per finding, for an assertion message.</summary>
    public string Summary
    {
        get
        {
            var text = new StringBuilder().Append(CultureInfo.InvariantCulture,
                $"{Signatures.Count} signature(s), {Successes} check(s) passed, {Failures.Count()} failure(s), {Warnings.Count()} warning(s)");
            foreach (var finding in Findings)
            {
                text.Append("\n  ").Append(finding);
            }

            return text.ToString();
        }
    }

    /// <summary>Reads the raw reports of a file's signatures.</summary>
    /// <param name="rawReports">Each signature's name and its <c>xmlrawoutput.xml</c>.</param>
    public static EtsiCheckerReport Parse(IReadOnlyDictionary<string, string> rawReports)
    {
        ArgumentNullException.ThrowIfNull(rawReports);
        int successes = 0;
        var findings = new List<EtsiFinding>();
        foreach (var (signature, xml) in rawReports.OrderBy(r => r.Key, StringComparer.Ordinal))
        {
            var root = XDocument.Parse(xml).Root ?? throw new FormatException($"The report of {signature} is empty.");
            foreach (var check in root.Descendants().Where(e => e.Name.LocalName.StartsWith("Check", StringComparison.Ordinal)))
            {
                string element = check.Name.LocalName;
                if (element == "CheckSuccess")
                {
                    successes++;
                    continue;
                }

                var outcome = element.Contains("Warning", StringComparison.Ordinal) ? EtsiCheckOutcome.Warning : EtsiCheckOutcome.Failure;
                string path = string.Join('/', check.Ancestors().Where(a => a != root).Reverse().Select(a => a.Name.LocalName));
                string message = string.Join(' ', check.Value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
                findings.Add(new EtsiFinding(signature, outcome, element, (string?)check.Attribute("check") ?? "", path, message));
            }
        }

        return new EtsiCheckerReport(rawReports, successes, findings);
    }
}
