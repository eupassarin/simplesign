extern alias cli;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Shouldly;
using SimpleSign.Brazil.GovBr;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.CAdES;
using SimpleSign.PAdES.DependencyInjection;
using SimpleSign.TestBench.Cades;
using SimpleSign.TestBench.Signing;
using SimpleSign.TestBench.Validation;
using SimpleSign.TestBench.Xml;
using SimpleSign.XAdES;
using Spectre.Console;
using Spectre.Console.Cli;
using CliNetwork = cli::SimpleSign.Cli.CliNetwork;
using CliProgram = cli::Program;
using CliRegistry = cli::SimpleSign.Cli.SimpleSignServiceRegistry;

namespace SimpleSign.TestBench.Tests;

/// <summary>
/// The CLI line the Code tab shows does what the library run did: each case signs through the TestBench
/// (the library), runs the generated <c>simplesign</c> command(s) through the real CLI, and validates both PDFs.
/// </summary>
[Collection(TestBenchCollection.Name)]
[Trait("Category", "Unit")]
public sealed partial class CliEquivalenceTests(TestBenchFixture fixture) : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("simplesign-cli-equivalence-").FullName;

    public static TheoryData<string> PadesCases() => Cases(s_pades.Keys);

    private static readonly Dictionary<string, Func<SigningOptions, SigningOptions>> s_pades = new(StringComparer.Ordinal)
    {
        ["B-B"] = o => o with { Level = BaselineLevel.BB },
        ["B-T"] = o => o with { Level = BaselineLevel.BT },
        ["B-LT, CRL first"] = o => o with { Level = BaselineLevel.BLT, RevocationPreference = Core.Signing.RevocationPreference.CrlFirst },
        ["B-LTA, separate archive TSA"] = o => o with { Level = BaselineLevel.BLTA, SeparateArchiveTsa = true },
        ["B-T, authenticated TSA"] = o => o with { Level = BaselineLevel.BT, Timestamp = new TimestampChoice { Provider = TsaProvider.SandboxAuthenticated } },
        ["SHA-384, PSS, larger /Contents"] = o => o with { Level = BaselineLevel.BB, Hash = HashChoice.Sha384, Padding = RsaPadding.Pss, ContentsReservedBytes = 32768 },
        ["adbe.pkcs7.detached, certification"] = o => o with
        {
            Level = BaselineLevel.BB,
            SubFilter = SubFilterChoice.AdbePkcs7Detached,
            Certification = CertificationChoice.FormFilling,
        },
        ["field texts, document info, signing time"] = o => o with
        {
            Level = BaselineLevel.BB,
            FieldName = "Aprovacao",
            Reason = "Aprovo",
            Location = "Brasília",
            ContactInfo = "a@b.c",
            SignerName = "Maria",
            DocumentInfo = [new("Title", "Contrato")],
            SigningTime = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero),
        },
        ["structured metadata"] = o => o with
        {
            Level = BaselineLevel.BB,
            UseSignerDetails = true,
            Metadata = new MetadataChoice { SignerName = "Maria da Silva", SignerId = "12345678909", SignerIdType = "CPF", LegalBasis = "Lei 14.063", CommitmentType = "ProofOfOrigin" },
        },
        ["explicit policy"] = o => o with
        {
            Level = BaselineLevel.BB,
            Kind = SignatureKind.CustomPolicy,
            CustomPolicy = new CustomPolicyChoice { Oid = "1.2.3.4.5", HashHex = Convert.ToHexString(SHA256.HashData("policy"u8)) },
        },
        ["deferred, B-T"] = o => o with { Mode = RunMode.Deferred, Level = BaselineLevel.BT },
        ["deferred, explicit policy, details and stamp"] = o => o with
        {
            Mode = RunMode.Deferred,
            Level = BaselineLevel.BB,
            Reason = "Aprovação",
            SignerName = "Maria",
            DocumentInfo = [new("Title", "Contrato")],
            SigningTime = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero),
            OperationId = "cli-two-phases",
            Kind = SignatureKind.CustomPolicy,
            CustomPolicy = new CustomPolicyChoice { Oid = "1.2.3.4.5", HashHex = Convert.ToHexString(SHA256.HashData("policy"u8)) },
            Appearance = o.Appearance with { Visible = true },
        },
        ["batch, B-T"] = o => o with { Mode = RunMode.Batch, Level = BaselineLevel.BT, BatchCopies = 2, MaxConcurrency = 2 },
    };

    [SkippableTheory]
    [MemberData(nameof(PadesCases))]
    public async Task GeneratedCli_Pades_SignsLikeTheLibrary(string name)
    {
        var options = s_pades[name](fixture.Options());
        var library = await fixture.Runner.RunAsync(options, default);
        library.Error.ShouldBeNull();
        library.Code.CliCommands.ShouldNotBeEmpty();

        var credential = fixture.Credentials.Get(options.CredentialId!);
        byte[] input = fixture.Documents.Get(options.DocumentId!).Content;
        await WriteInputsAsync(credential.Certificate, input, options.Mode == RunMode.Batch ? options.BatchCopies : 0);

        foreach (var command in library.Code.CliCommands)
        {
            if (command.Args[0] == "deferred" && command.Args[1] == "complete")
            {
                SignOutside(options.Padding == RsaPadding.Pss);
            }

            var (exit, output) = await RunAsync(command.Args);
            exit.ShouldBe(0, $"{command}\n{output}");
        }

        byte[] cliPdf = options.Mode == RunMode.Batch
            ? await File.ReadAllBytesAsync(Path.Combine(_dir, CliLine.Placeholders.OutputFolder, "document-1.pdf"))
            : await File.ReadAllBytesAsync(Path.Combine(_dir, CliLine.Placeholders.Output));
        var cli = await fixture.Validation.ValidateAsync(cliPdf, options.Validation ?? new ValidationSettings(), default);
        Summary(cli).ShouldBe(Summary(library.Validation), string.Join("\n", library.Code.CliCommands));
    }

    public static TheoryData<string> CadesCases() => Cases(s_cades.Keys);

    private static readonly Dictionary<string, Func<CadesOptions, CadesOptions>> s_cades = new(StringComparer.Ordinal)
    {
        ["B-B detached"] = o => o,
        ["B-T enveloped"] = o => o with { Level = BaselineLevel.BT, ContentType = CadesContentChoice.Enveloped },
        ["B-LT, CRL first, authenticated TSA"] = o => o with
        {
            Level = BaselineLevel.BLT,
            RevocationPreference = Core.Signing.RevocationPreference.CrlFirst,
            Timestamp = new TimestampChoice { Provider = TsaProvider.SandboxAuthenticated },
        },
        ["SHA-384, PSS, signing time, content timestamp"] = o => o with
        {
            Hash = HashChoice.Sha384,
            Padding = RsaPadding.Pss,
            SigningTime = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero),
            ContentTimestamp = true,
        },
        ["B-LT, CAdES-X Long"] = o => o with { Level = BaselineLevel.BLT, ExtendedForm = CadesExtendedChoice.ExtendedLong },
    };

    [SkippableTheory]
    [MemberData(nameof(CadesCases))]
    public async Task GeneratedCli_Cades_SignsLikeTheLibrary(string name)
    {
        var options = s_cades[name](new CadesOptions { DataId = CadesSample("text"), CredentialId = fixture.Sandboxed() });
        await CadesEquivalentAsync(options);
    }

    [SkippableTheory]
    [InlineData("detached")]
    [InlineData("enveloped")]
    public async Task GeneratedCli_CadesCoSign_SignsLikeTheLibrary(string existing)
    {
        var sample = fixture.CadesSamples.Single(s => s.Id == existing);
        await CadesEquivalentAsync(new CadesOptions
        {
            Operation = CadesOperation.CoSign,
            ExistingSignatureId = sample.FileId,
            DataId = sample.DataId,
            CredentialId = fixture.Sandboxed("rsa-3072"),
        });
    }

    [SkippableFact]
    public async Task GeneratedCli_CadesCounterSign_SignsLikeTheLibrary() =>
        await CadesEquivalentAsync(new CadesOptions
        {
            Operation = CadesOperation.CounterSign,
            ExistingSignatureId = CadesSample("enveloped"),
            CredentialId = fixture.Sandboxed(),
        });

    public static TheoryData<string> XadesCases() => Cases(s_xades.Keys);

    private static readonly Dictionary<string, Func<XmlOptions, XmlOptions>> s_xades = new(StringComparer.Ordinal)
    {
        ["B-B enveloped"] = o => o,
        ["B-T enveloping"] = o => o with { Level = BaselineLevel.BT, Form = XadesFormChoice.Enveloping },
        ["B-LT, authenticated TSA"] = o => o with { Level = BaselineLevel.BLT, Timestamp = new TimestampChoice { Provider = TsaProvider.SandboxAuthenticated } },
        ["V1, MIME type, PSS, signing time"] = o => o with
        {
            SigningCertificateV1 = true,
            MimeType = "application/xml",
            Padding = RsaPadding.Pss,
            SigningTime = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero),
        },
        ["B-T, XAdES-X Long"] = o => o with { Level = BaselineLevel.BT, ExtendedForm = XadesExtendedChoice.ExtendedLong },
    };

    [SkippableTheory]
    [MemberData(nameof(XadesCases))]
    public async Task GeneratedCli_Xades_SignsLikeTheLibrary(string name)
    {
        var options = s_xades[name](new XmlOptions { DataId = fixture.XmlSamples.Single(s => s.Id == "order").FileId, CredentialId = fixture.Sandboxed() });
        var library = await fixture.Xml.RunAsync(options, default);
        library.Error.ShouldBeNull(string.Join("; ", library.Issues.Select(i => i.Message)));
        var credential = fixture.Credentials.Get(options.CredentialId!);
        await WriteInputsAsync(credential.Certificate, [], 0);
        await File.WriteAllBytesAsync(Path.Combine(_dir, XmlRunner.DataFile), fixture.Documents.Get(options.DataId!).Content);

        string written = await RunAllAsync(library.Code.CliCommands);

        string id = fixture.Documents.Add("cli.xml", await File.ReadAllBytesAsync(written)).Id;
        var cli = await fixture.Xml.ValidateAsync(id, null, options.Validation ?? new ValidationSettings());
        Summary(cli).ShouldBe(Summary(library.Validation!), string.Join("\n", library.Code.CliCommands));
    }

    private string CadesSample(string id) => fixture.CadesSamples.Single(s => s.Id == id).FileId;

    /// <summary>Signs with the library and with the generated CLI line, and validates both CMS alike.</summary>
    private async Task CadesEquivalentAsync(CadesOptions options)
    {
        var library = await fixture.Cades.RunAsync(options, default);
        library.Error.ShouldBeNull(string.Join("; ", library.Issues.Select(i => i.Message)));
        var credential = fixture.Credentials.Get(options.CredentialId!);
        await WriteInputsAsync(credential.Certificate, [], 0);
        if (options.DataId is not null)
        {
            await File.WriteAllBytesAsync(Path.Combine(_dir, CadesRunner.DataFile), fixture.Documents.Get(options.DataId).Content);
        }

        if (options.ExistingSignatureId is not null)
        {
            await File.WriteAllBytesAsync(Path.Combine(_dir, CadesRunner.SignatureFile), fixture.Documents.Get(options.ExistingSignatureId).Content);
        }

        string written = await RunAllAsync(library.Code.CliCommands);

        string id = fixture.Documents.Add("cli.p7s", await File.ReadAllBytesAsync(written)).Id;
        bool detached = options.Operation != CadesOperation.CounterSign && options.ContentType == CadesContentChoice.Detached && options.DataId is not null;
        var cli = await fixture.Cades.ValidateAsync(id, detached ? options.DataId : null, options.Validation ?? new ValidationSettings());
        Summary(cli).ShouldBe(Summary(library.Validation!), string.Join("\n", library.Code.CliCommands));
    }

    private static IReadOnlyList<string> Summary(CadesValidationView view) =>
        [view.Overall, .. view.Signers.Select(s => $"{s.Index} | {s.Indication} | countersignatures {s.CounterSignatures.Count}")];

    private static IReadOnlyList<string> Summary(XmlValidationView view) =>
        [view.Overall, .. view.Signatures.Select(s => $"{s.Index} | {s.Indication} | {s.Level}")];

    private static TheoryData<string> Cases(IEnumerable<string> names)
    {
        var cases = new TheoryData<string>();
        foreach (string name in names)
        {
            cases.Add(name);
        }

        return cases;
    }

    /// <summary>Runs every generated command, each expected to succeed; returns the file the last one wrote (its --output).</summary>
    private async Task<string> RunAllAsync(IReadOnlyList<CliLine> commands)
    {
        commands.ShouldNotBeEmpty();
        string written = "";
        foreach (var command in commands)
        {
            var (exit, output) = await RunAsync(command.Args);
            exit.ShouldBe(0, $"{command}\n{output}");
            int index = command.Args.ToList().IndexOf("--output");
            written = index < 0 ? written : Path.Combine(_dir, command.Args[index + 1]);
        }

        File.Exists(written).ShouldBeTrue($"{written}: {string.Join(", ", Directory.GetFiles(_dir).Select(Path.GetFileName))}");
        return written;
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    /// <summary>The name of a document-timestamp field ends with the second it was made: the two runs differ there.</summary>
    [System.Text.RegularExpressions.GeneratedRegex(@"^DocTimeStamp_\d+$")]
    private static partial System.Text.RegularExpressions.Regex DocTimeStamp();

    /// <summary>What both runs must agree on, per signature: field, verdict, kind, sub-filter, digest and declared texts.</summary>
    private static IReadOnlyList<string> Summary(IReadOnlyList<SignatureReport> reports) =>
        [.. reports.Select(r => string.Join(" | ", DocTimeStamp().Replace(r.FieldName, "DocTimeStamp"), r.Indication, r.IsDocumentTimestamp, r.SubFilter, r.Digest,
            string.Join(";", (r.Metadata ?? new Dictionary<string, string>()).Where(m => !m.Key.Contains("time", StringComparison.OrdinalIgnoreCase)).OrderBy(m => m.Key, StringComparer.Ordinal).Select(m => $"{m.Key}={m.Value}"))))];

    /// <summary>
    /// The files the placeholders name: the document (or a folder of copies), the signer's PFX (as the Sandbox serves
    /// it: the TestBench's own copy of the key cannot be exported on every OS) and certificate, and the root.
    /// </summary>
    private async Task WriteInputsAsync(X509Certificate2 signer, byte[] pdf, int copies)
    {
        await File.WriteAllBytesAsync(Path.Combine(_dir, CliLine.Placeholders.Input), pdf);
        if (copies > 0)
        {
            string folder = Directory.CreateDirectory(Path.Combine(_dir, CliLine.Placeholders.InputFolder)).FullName;
            for (int i = 1; i <= copies; i++)
            {
                await File.WriteAllBytesAsync(Path.Combine(folder, $"document-{i}.pdf"), pdf);
            }
        }

        using var http = new HttpClient();
        byte[] pfx = await http.GetByteArrayAsync(new Uri(TestBenchFixture.SandboxUrl, "api/certificates/rsa-2048/pfx"));
        await File.WriteAllBytesAsync(Path.Combine(_dir, CliLine.Placeholders.SignerPfx), pfx);
        await File.WriteAllBytesAsync(Path.Combine(_dir, CliLine.Placeholders.SignerCertificate), signer.Export(X509ContentType.Cert));
        await File.WriteAllBytesAsync(Path.Combine(_dir, ValidationService.RootFile), fixture.Sandbox.Connection.Root.Export(X509ContentType.Cert));
        if (fixture.Sandbox.Connection.LotlSigner is { } lotlSigner)
        {
            await File.WriteAllTextAsync(Path.Combine(_dir, ValidationService.LotlSignerFile), lotlSigner.ExportCertificatePem());
        }

        await File.WriteAllTextAsync(Path.Combine(_dir, CliLine.Placeholders.Chain),
            string.Concat(fixture.Sandbox.Connection.Chain.Select(c => c.ExportCertificatePem() + "\n")));
    }

    /// <summary>The signer that is elsewhere: signs the data to sign that <c>deferred prepare</c> wrote, with the PFX's key.</summary>
    private void SignOutside(bool pss)
    {
        byte[] toSign = File.ReadAllBytes(Path.Combine(_dir, CliLine.Placeholders.Input + ".tbs"));
        using var signer = X509CertificateLoader.LoadPkcs12FromFile(Path.Combine(_dir, CliLine.Placeholders.SignerPfx), PfxPassword);
        using var rsa = signer.GetRSAPrivateKey()!;
        File.WriteAllBytes(Path.Combine(_dir, CliLine.Placeholders.Signature),
            rsa.SignData(toSign, HashAlgorithmName.SHA256, pss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1));
    }

    private string PfxPassword => fixture.Sandbox.Connection.Info.PfxPassword;

    private static readonly SemaphoreSlim s_cli = new(1, 1);

    /// <summary>Runs one generated command through the CLI, its file names resolved in the work folder.</summary>
    private async Task<(int Exit, string Output)> RunAsync(IReadOnlyList<string> args)
    {
        string[] resolved = [.. args.Select((a, i) => Resolve(a, i > 0 && args[i - 1] is "--output" or "--output-dir"))];
        await s_cli.WaitAsync();
        IAnsiConsole originalAnsi = AnsiConsole.Console;
        TextWriter originalOut = Console.Out;
        using var stdout = new StringWriter();
        var recorder = new Recorder(AnsiConsole.Create(new AnsiConsoleSettings { Out = new AnsiConsoleOutput(stdout), Interactive = InteractionSupport.No }));
        try
        {
            AnsiConsole.Console = recorder;
            Console.SetOut(stdout);
            string[] commandArgs = CliNetwork.Configure(resolved);
            var services = new ServiceCollection();
            if (CliNetwork.IsConfigured)
            {
                services.AddSimpleSign(configure: null, CliNetwork.Provider);
            }
            else
            {
                services.AddSimpleSign();
            }

            services.AddSimpleSignIcpBrasil();
            services.AddSimpleSignGovBr();
            services.AddSimpleSignCades();
            services.AddSimpleSignXades();
            var app = new CommandApp(new CliRegistry(services));
            app.Configure(c => c.PropagateExceptions());
            CliProgram.ConfigureApp(app);
            int exit = await CliProgram.RunWithAsync(app, commandArgs);
            return (exit, stdout.ToString());
        }
        catch (Exception ex)
        {
            return (-1, stdout + ex.ToString());
        }
        finally
        {
            AnsiConsole.Console = originalAnsi;
            Console.SetOut(originalOut);
            s_cli.Release();
        }
    }

    /// <summary>
    /// A token with the placeholders filled in: the secrets, and file names (those in the work folder, and the
    /// outputs the commands write) as paths in it.
    /// </summary>
    private string Resolve(string token, bool isOutput)
    {
        if (token is CliLine.Placeholders.PfxPassword or CliLine.Placeholders.TsaClientPassword)
        {
            return PfxPassword;
        }

        if (token == CliLine.Placeholders.SessionKey)
        {
            return new string('a', 64);
        }

        string path = Path.Combine(_dir, token);
        bool isFile = !token.StartsWith('-') && !token.Contains("://", StringComparison.Ordinal)
            && (isOutput || File.Exists(path) || Directory.Exists(path) || token == CliLine.Placeholders.Signature);
        return isFile ? path : token;
    }
}
