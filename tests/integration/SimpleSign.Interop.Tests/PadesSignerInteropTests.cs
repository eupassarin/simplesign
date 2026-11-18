using System.Text;
using Shouldly;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestHelpers;
using Xunit;
using Xunit.Abstractions;

namespace SimpleSign.Interop.Tests;

/// <summary>
/// What <see cref="PadesSigner"/> writes, read by two independent implementations: qpdf (the PDF syntax and the
/// cross-reference chain of every incremental update) and pyHanko (each signature and document timestamp intact,
/// cryptographically valid, chained to the test root, covering what it should). Every level, a visible appearance, a
/// second signature, a certification and an ECDSA key, on a classic cross-reference table and a cross-reference stream.
/// </summary>
[Trait("Category", "Interop")]
public sealed class PadesSignerInteropTests(OfflinePki pki, ITestOutputHelper output) : IClassFixture<OfflinePki>
{
    /// <summary>Every source document with every way of signing it.</summary>
    public static TheoryData<string, string> Cases
    {
        get
        {
            var data = new TheoryData<string, string>();
            foreach (string source in Sources)
            {
                foreach (string scenario in Scenarios)
                {
                    data.Add(source, scenario);
                }
            }

            return data;
        }
    }

    /// <summary>Three pages, made by qpdf: a classic cross-reference table and a cross-reference stream (object streams).</summary>
    private static readonly string[] Sources = ["xref-table.pdf", "xref-stream.pdf"];

    private static readonly string[] Scenarios = ["B-B", "B-B-visible", "B-T", "B-LT", "B-LTA", "two-signatures", "certified", "ecdsa"];

    [SkippableTheory(DisplayName = "qpdf: every PDF SimpleSign signs has a sound syntax and cross-reference chain")]
    [MemberData(nameof(Cases))]
    public async Task SignAsync_AnyScenario_PassesQpdfCheck(string source, string scenario)
    {
        InteropTools.Require(InteropTool.Qpdf);
        byte[] signed = await SignAsync(source, scenario);

        var check = await InteropTools.RunAsync(InteropTool.Qpdf, "--check", pki.Write("signed.pdf", signed));
        output.WriteLine(check.Output);

        if (check.ExitCode != 0)
        {
            output.WriteLine($"Saved to {InteropTools.SaveRejected($"qpdf-{scenario}-{source}", signed)}");
        }

        check.ExitCode.ShouldBe(0, check.Output);
        check.Stdout.ShouldContain("No syntax or stream encoding errors found");
    }

    [SkippableTheory(DisplayName = "pyHanko: every signature and timestamp SimpleSign writes is intact, valid and trusted")]
    [MemberData(nameof(Cases))]
    public async Task SignAsync_AnyScenario_PyHankoValidates(string source, string scenario)
    {
        InteropTools.Require(InteropTool.PyHanko);
        byte[] signed = await SignAsync(source, scenario);

        var signatures = await InteropTools.PyHankoValidateAsync(pki.Write("signed.pdf", signed), pki.RootPem);
        signatures.ShouldNotBeEmpty();
        foreach (var signature in signatures)
        {
            output.WriteLine($"{signature.Field} ({signature.Kind}): {signature.Summary ?? signature.Error}, coverage {signature.Coverage}, modifications {signature.ModificationLevel}");
        }

        var problems = Problems(signatures).ToList();
        if (problems.Count > 0)
        {
            output.WriteLine($"Saved to {InteropTools.SaveRejected($"pyhanko-{scenario}-{source}", signed)}");
        }

        problems.ShouldBeEmpty();
        signatures.Count.ShouldBe(scenario switch
        {
            "two-signatures" => 2,
            "B-LTA" => 2, // the signature and the document timestamp
            _ => 1,
        });
    }

    /// <summary>The control: qpdf must notice a <c>startxref</c> that points to the wrong place.</summary>
    [SkippableFact(DisplayName = "qpdf: a signed PDF whose startxref is wrong fails the check")]
    public async Task QpdfCheck_WrongStartXref_Fails()
    {
        InteropTools.Require(InteropTool.Qpdf);
        byte[] signed = await SignAsync("xref-table.pdf", "B-B");

        byte[] broken = WrongStartXref(signed);
        var check = await InteropTools.RunAsync(InteropTool.Qpdf, "--check", pki.Write("broken.pdf", broken));
        output.WriteLine(check.Output);

        check.ExitCode.ShouldNotBe(0);
    }

    /// <summary>The control: pyHanko must notice a change to the bytes a signature covers.</summary>
    [SkippableFact(DisplayName = "pyHanko: a change to the signed bytes leaves the signature not intact")]
    public async Task PyHankoValidate_SignedBytesChanged_NotIntact()
    {
        InteropTools.Require(InteropTool.PyHanko);
        byte[] signed = await SignAsync("xref-table.pdf", "B-B");

        byte[] changed = Replace(signed, "/MediaBox [ 0 0 612 792 ]", "/MediaBox [ 0 0 612 793 ]");
        var signatures = await InteropTools.PyHankoValidateAsync(pki.Write("changed.pdf", changed), pki.RootPem);
        output.WriteLine(string.Join("\n", signatures.Select(s => s.Summary ?? s.Error)));

        signatures.ShouldHaveSingleItem().Intact.ShouldBeFalse();
    }

    private Task<byte[]> SignAsync(string source, string scenario) =>
        SignAsync(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", source)), scenario);

    private async Task<byte[]> SignAsync(byte[] pdf, string scenario)
    {
        var signer = PadesSigner.Document(pdf).WithCertificate(pki.Pki.Leaf, pki.Chain).WithHttpClientProvider(pki.Http);
        return scenario switch
        {
            "B-B" => await signer.SignAsync(),
            "B-B-visible" => await signer.WithAppearance(SignatureAppearance.Auto()).SignAsync(),
            "B-T" => await signer.WithLevel(pki.Level("T")).SignAsync(),
            "B-LT" => await signer.WithLevel(pki.Level("LT")).SignAsync(),
            "B-LTA" => await signer.WithLevel(pki.Level("LTA")).SignAsync(),
            "two-signatures" => await PadesSigner.Document(await signer.SignAsync())
                .WithCertificate(pki.Ecdsa, pki.Chain).WithHttpClientProvider(pki.Http).WithLevel(pki.Level("T")).SignAsync(),
            "certified" => await signer.AsCertification(CertificationLevel.FormFilling).SignAsync(),
            "ecdsa" => await PadesSigner.Document(pdf).WithCertificate(pki.Ecdsa, pki.Chain).WithHttpClientProvider(pki.Http).SignAsync(),
            _ => throw new ArgumentOutOfRangeException(nameof(scenario), scenario, null),
        };
    }

    /// <summary>What pyHanko found wrong, one line per problem; empty when every signature passes.</summary>
    private static IEnumerable<string> Problems(IReadOnlyList<PyHankoSignature> signatures)
    {
        for (int i = 0; i < signatures.Count; i++)
        {
            var s = signatures[i];
            string name = $"{s.Field} ({s.Kind})";
            if (s.Error is not null)
            {
                yield return $"{name}: {s.Error}";
                continue;
            }

            if (!s.Intact || !s.Valid || !s.Trusted)
            {
                yield return $"{name}: intact {s.Intact}, valid {s.Valid}, trusted {s.Trusted} ({s.Summary})";
            }

            if (s.TimestampTrusted == false)
            {
                yield return $"{name}: its signature timestamp is not trusted";
            }

            if (s.DocmdpOk == false)
            {
                yield return $"{name}: DocMDP broken";
            }

            // The last revision covers the whole file. One followed by SimpleSign's own updates (a DSS, a document
            // timestamp, another signature) covers its revision, and pyHanko must class what came after as allowed.
            if (i == signatures.Count - 1 && s.Coverage != "ENTIRE_FILE" && s.ModificationLevel != "LTA_UPDATES")
            {
                yield return $"{name}: coverage {s.Coverage} ({s.ModificationLevel}), expected ENTIRE_FILE";
            }

            if (s.Coverage is not ("ENTIRE_FILE" or "ENTIRE_REVISION"))
            {
                yield return $"{name}: coverage {s.Coverage}";
            }

            if (s.ModificationLevel is not (null or "NONE" or "LTA_UPDATES" or "FORM_FILLING"))
            {
                yield return $"{name}: later revisions classed as {s.ModificationLevel}";
            }
        }
    }

    private static byte[] WrongStartXref(byte[] pdf)
    {
        string text = Encoding.Latin1.GetString(pdf);
        int keyword = text.LastIndexOf("startxref", StringComparison.Ordinal);
        int start = keyword + "startxref".Length;
        while (!char.IsAsciiDigit(text[start]))
        {
            start++;
        }

        int end = start;
        while (char.IsAsciiDigit(text[end]))
        {
            end++;
        }

        // Same length, so nothing else moves: the offset drops by one into the byte before the cross-reference section.
        long offset = long.Parse(text[start..end], System.Globalization.CultureInfo.InvariantCulture);
        string wrong = (offset - 1).ToString(System.Globalization.CultureInfo.InvariantCulture).PadLeft(end - start, '0');
        return Encoding.Latin1.GetBytes(string.Concat(text.AsSpan(0, start), wrong, text.AsSpan(end)));
    }

    private static byte[] Replace(byte[] pdf, string find, string replacement)
    {
        string text = Encoding.Latin1.GetString(pdf);
        int at = text.IndexOf(find, StringComparison.Ordinal);
        at.ShouldBeGreaterThanOrEqualTo(0, $"{find} not found");
        return Encoding.Latin1.GetBytes(string.Concat(text.AsSpan(0, at), replacement, text.AsSpan(at + find.Length)));
    }
}
