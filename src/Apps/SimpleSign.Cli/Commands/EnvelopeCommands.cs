using System.ComponentModel;
using System.Globalization;
using System.Text.Json;
using SimpleSign.Cli.Extensions;
using SimpleSign.Cli.Json;
using SimpleSign.Cli.Rendering;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES.Envelope;
using SimpleSign.PAdES.Signing;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Commands;

/// <summary>The levels a field of an envelope can ask for, by id: the library's, then the extensions' (ADR 0033).</summary>
internal static class EnvelopeLevels
{
    private static IReadOnlyList<EnvelopeLevel> Library { get; } =
        [EnvelopeLevel.Any, EnvelopeLevel.PadesB, EnvelopeLevel.PadesT, EnvelopeLevel.PadesLt, EnvelopeLevel.PadesLta];

    /// <summary>Every level known, the library's first.</summary>
    public static IReadOnlyList<EnvelopeLevel> All => [.. Library, .. CliExtensions.Active.SelectMany(e => e.EnvelopeLevels)];

    /// <summary>The level of an id; null when no level has it.</summary>
    public static EnvelopeLevel? Find(string id) => All.FirstOrDefault(l => string.Equals(l.Id, id, StringComparison.OrdinalIgnoreCase));

    /// <summary>The ids, for a message.</summary>
    public static string Names => string.Join(", ", All.Select(l => l.Id));
}

/// <summary>
/// Reads a signer as <c>--signer</c> writes it: <c>key=value</c> pairs separated by semicolons
/// (<c>name=Maria Silva;id=CPF:52998224725;also=RESPONSIBLE-CPF;role=Diretora;email=maria@x.com;level=icp-ad-rt;page=1;rect=72,72,200,50;external</c>).
/// <c>id=TYPE:VALUE</c> may be repeated; <c>also=TYPE</c> adds a type accepted for the <c>id</c> before it.
/// </summary>
internal static class EnvelopeSignerSpec
{
    public static EnvelopeSigner Parse(string spec)
    {
        string? name = null, role = null, email = null;
        bool external = false;
        var level = EnvelopeLevel.Any;
        int page = 1;
        float[]? rect = null;
        var identifiers = new List<EnvelopeIdentifier>();
        var reasons = new List<string>();
        foreach (string part in spec.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            int eq = part.IndexOf('=', StringComparison.Ordinal);
            string key = (eq < 0 ? part : part[..eq]).Trim().ToLowerInvariant();
            string value = eq < 0 ? "" : part[(eq + 1)..].Trim();
            switch (key)
            {
                case "name":
                    name = value;
                    break;
                case "role":
                    role = value;
                    break;
                case "email":
                    email = value;
                    break;
                case "reason":
                    reasons.Add(value);
                    break;
                case "external":
                    external = eq < 0 || bool.Parse(value);
                    break;
                case "level":
                    level = EnvelopeLevels.Find(value) ?? throw new FormatException($"Unknown level '{value}': use {EnvelopeLevels.Names}.");
                    break;
                case "page":
                    page = int.Parse(value, NumberStyles.None, CultureInfo.InvariantCulture);
                    break;
                case "rect":
                    rect = [.. value.Split(',').Select(v => float.Parse(v.Trim(), NumberStyles.Float, CultureInfo.InvariantCulture))];
                    if (rect.Length != 4)
                    {
                        throw new FormatException($"rect needs four numbers, x,y,width,height: '{value}'.");
                    }

                    break;
                case "id":
                    int colon = value.IndexOf(':', StringComparison.Ordinal);
                    if (colon <= 0 || colon == value.Length - 1)
                    {
                        throw new FormatException($"id needs TYPE:VALUE, such as CPF:52998224725: '{value}'.");
                    }

                    identifiers.Add(new EnvelopeIdentifier(value[..colon].Trim().ToUpperInvariant(), value[(colon + 1)..].Trim()));
                    break;
                case "also":
                    if (identifiers.Count == 0)
                    {
                        throw new FormatException("also= follows an id=.");
                    }

                    var last = identifiers[^1];
                    identifiers[^1] = last with { AlsoAccept = [.. last.AlsoAccept, value.ToUpperInvariant()] };
                    break;
                default:
                    throw new FormatException($"Unknown signer key '{key}': use name, id, also, role, email, reason, level, page, rect, external.");
            }
        }

        if (string.IsNullOrWhiteSpace(name))
        {
            throw new FormatException($"The signer has no name: '{spec}'.");
        }

        if (rect is null)
        {
            throw new FormatException($"The signer '{name}' has no rect=x,y,width,height.");
        }

        return new EnvelopeSigner
        {
            Name = name,
            Role = role,
            Email = email,
            External = external,
            Level = level,
            Identifiers = identifiers,
            Reasons = reasons,
            Placement = new EnvelopePlacement(page, rect[0], rect[1], rect[2], rect[3]),
        };
    }
}

/// <summary>Prepares a signature envelope in a PDF (ADR 0033).</summary>
[Description("Prepare a signature envelope in a PDF: one field per signer, and the manifest, before any signature")]
internal sealed class EnvelopePrepareCommand : AsyncCommand<EnvelopePrepareCommand.Settings>
{
    /// <summary>Envelope prepare settings.</summary>
    internal sealed class Settings : CommonSettings
    {
        /// <summary>The PDF, not signed yet.</summary>
        [CommandArgument(0, "<input>")]
        [Description("The PDF, not signed yet")]
        public string InputPath { get; init; } = null!;

        /// <summary>Where the prepared PDF goes.</summary>
        [CommandOption("--output|-o <PATH>")]
        [Description("Where the prepared PDF goes (default: <input>-envelope.pdf)")]
        public string? OutputPath { get; init; }

        /// <summary>The signers, in order.</summary>
        [CommandOption("--signer <SPEC>")]
        [Description("A signer, in order: \"name=…;id=TYPE:VALUE;also=TYPE;role=…;email=…;reason=…;level=…;page=N;rect=x,y,w,h;external\" (repeat for each)")]
        public string[] Signers { get; init; } = [];

        /// <summary>The order.</summary>
        [CommandOption("--order <ORDER>")]
        [Description("sequential (default) or parallel")]
        public string Order { get; init; } = "sequential";

        /// <summary>The time-stamp server written in the seed values of fields that need one.</summary>
        [CommandOption("--tsa <URL>")]
        [Description("The time-stamp server written in the seed values of the fields whose level needs one")]
        public string? TsaUrl { get; init; }

        /// <summary>The certification the first signer is asked to make.</summary>
        [CommandOption("--certify <LEVEL>")]
        [Description("Ask the first signer to certify (DocMDP): form-filling, annotations, no-changes (one signer only)")]
        public string? Certify { get; init; }

        /// <summary>Whether the last field locks the document.</summary>
        [CommandOption("--lock-document")]
        [Description("The last field of a sequential envelope locks the document once signed")]
        public bool LockDocument { get; init; }

        /// <summary>Output as JSON.</summary>
        [CommandOption("--json")]
        [Description("Write the manifest as JSON")]
        public bool Json { get; init; }

        public override ValidationResult Validate()
        {
            if (!File.Exists(InputPath))
            {
                return ValidationResult.Error($"File not found: {InputPath}");
            }

            if (Signers.Length == 0)
            {
                return ValidationResult.Error("Give at least one --signer.");
            }

            if (Order is not ("sequential" or "parallel"))
            {
                return ValidationResult.Error("--order is sequential or parallel.");
            }

            return TsaUrl is not null && !Uri.TryCreate(TsaUrl, UriKind.Absolute, out _)
                ? ValidationResult.Error($"--tsa is not a URL: {TsaUrl}")
                : ValidationResult.Success();
        }
    }

    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        PdfEnvelopeBuilder builder;
        try
        {
            builder = PdfEnvelope.Prepare(await File.ReadAllBytesAsync(settings.InputPath, cancellationToken))
                .WithOrder(settings.Order == "parallel" ? EnvelopeOrder.Parallel : EnvelopeOrder.Sequential);
            foreach (string spec in settings.Signers)
            {
                builder = builder.AddSigner(EnvelopeSignerSpec.Parse(spec));
            }
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException or OverflowException)
        {
            AnsiConsole.MarkupLine($"[red]Error:[/] {ex.Message.EscapeMarkup()}");
            return 1;
        }

        if (settings.TsaUrl is not null)
        {
            builder = builder.WithTimestampUrl(new Uri(settings.TsaUrl));
        }

        if (settings.Certify is not null)
        {
            builder = builder.WithCertification(SignCommandOptions.ParseCertificationLevel(settings.Certify));
        }

        if (settings.LockDocument)
        {
            builder = builder.WithDocumentLock();
        }

        string output = settings.OutputPath ?? Path.Combine(
            Path.GetDirectoryName(Path.GetFullPath(settings.InputPath))!, Path.GetFileNameWithoutExtension(settings.InputPath) + "-envelope.pdf");
        try
        {
            var manifest = builder.BuildManifest();
            await File.WriteAllBytesAsync(output, await builder.PrepareAsync(cancellationToken), cancellationToken);
            if (settings.Json)
            {
                Console.WriteLine(manifest.ToJson());
            }
            else
            {
                AnsiConsole.MarkupLine($"[green]✓[/] Envelope prepared: [bold]{output.EscapeMarkup()}[/]");
                foreach (var signer in manifest.Signers)
                {
                    AnsiConsole.MarkupLine($"  {signer.Field.EscapeMarkup()}  {signer.Name.EscapeMarkup()}  [dim]{signer.Level.Id.EscapeMarkup()}[/]");
                }
            }

            return 0;
        }
        catch (Exception ex) when (ex is SigningException or InvalidOperationException or ArgumentException or PAdES.Pdf.Exceptions.PdfStructureException)
        {
            string reason = ex is SigningException signing ? $" ({signing.Reason})" : "";
            AnsiConsole.MarkupLine($"[red]Error{reason.EscapeMarkup()}:[/] {ex.Message.EscapeMarkup()}");
            return 1;
        }
    }
}

/// <summary>Shows where an envelope stands (ADR 0033).</summary>
[Description("Show a PDF's signature envelope: its fields, what is signed, and who signs next")]
internal sealed class EnvelopeStatusCommand : Command<EnvelopeStatusCommand.Settings>
{
    /// <summary>Envelope status settings.</summary>
    internal sealed class Settings : CommonSettings
    {
        /// <summary>The PDF.</summary>
        [CommandArgument(0, "<input>")]
        [Description("The PDF with the envelope")]
        public string InputPath { get; init; } = null!;

        /// <summary>Output as JSON.</summary>
        [CommandOption("--json")]
        [Description("Output as JSON (machine-readable)")]
        public bool Json { get; init; }

        public override ValidationResult Validate() =>
            File.Exists(InputPath) ? ValidationResult.Success() : ValidationResult.Error($"File not found: {InputPath}");
    }

    public override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
    {
        var envelope = PdfEnvelopeReader.Read(File.ReadAllBytes(settings.InputPath));
        if (envelope is null)
        {
            AnsiConsole.MarkupLine("[yellow]The PDF holds no signature envelope.[/]");
            return 1;
        }

        if (settings.Json)
        {
            var output = new EnvelopeStatusOutput
            {
                Id = envelope.Manifest?.Id,
                Status = envelope.Status.ToString(),
                Order = envelope.Manifest?.Order.ToString(),
                Next = envelope.Next?.Name,
                Problems = [.. envelope.Problems],
                Fields = [.. envelope.Fields.Select(f => new EnvelopeFieldOutput
                {
                    Name = f.Name,
                    Signer = f.Signer?.Name,
                    Role = f.Signer?.Role,
                    Level = f.Signer?.Level.Id,
                    Page = f.Placement?.Page,
                    IsSigned = f.IsSigned,
                    SignedBy = f.SignerName,
                    SigningTime = f.SigningTime,
                    SignatureOrder = f.SignatureOrder,
                })],
            };
            Console.WriteLine(JsonSerializer.Serialize(output, CliJsonContext.Default.EnvelopeStatusOutput));
            return envelope.Status == EnvelopeStatus.Inconsistent ? 1 : 0;
        }

        AnsiConsole.MarkupLine($"Envelope [bold]{(envelope.Manifest?.Id ?? "?").EscapeMarkup()}[/]: {envelope.Status} ({envelope.Manifest?.Order.ToString() ?? "?"})");
        var table = new Table().AddColumns("Field", "Signer", "Level", "Page", "Signed");
        foreach (var field in envelope.Fields)
        {
            table.AddRow(
                field.Name.EscapeMarkup(),
                (field.Signer?.Name ?? "—").EscapeMarkup(),
                (field.Signer?.Level.Id ?? "—").EscapeMarkup(),
                field.Placement?.Page.ToString(CultureInfo.InvariantCulture) ?? "—",
                field.IsSigned ? $"[green]✓[/] {(field.SignerName ?? "").EscapeMarkup()}" : "[dim]no[/]");
        }

        AnsiConsole.Write(table);
        if (envelope.Next is { } next)
        {
            AnsiConsole.MarkupLine($"Next: [bold]{next.Name.EscapeMarkup()}[/] ({(next.Signer?.Name ?? "").EscapeMarkup()})");
        }

        foreach (string problem in envelope.Problems)
        {
            AnsiConsole.MarkupLine($"[red]✗[/] {problem.EscapeMarkup()}");
        }

        return envelope.Status == EnvelopeStatus.Inconsistent ? 1 : 0;
    }
}

/// <summary>Writes the validation of an envelope (<c>validate --envelope</c>).</summary>
internal static class EnvelopeReport
{
    /// <summary>Validates the envelope and writes the report; 0 when it is complete.</summary>
    public static async Task<int> WriteAsync(PdfEnvelopeValidator validator, string path, bool json, CancellationToken cancellationToken)
    {
        PdfEnvelopeReport report;
        try
        {
            report = await validator.ValidateAsync(await File.ReadAllBytesAsync(path, cancellationToken), cancellationToken);
        }
        catch (SigningException ex)
        {
            AnsiConsole.MarkupLine($"[yellow]{ex.Message.EscapeMarkup()}[/]");
            return 1;
        }

        if (json)
        {
            Console.WriteLine(report.ToJson());
            return report.IsComplete ? 0 : 1;
        }

        string verdict = report.IsComplete ? "[green]✓ complete[/]" : "[red]✗ not complete[/]";
        AnsiConsole.MarkupLine($"Envelope [bold]{(report.Envelope.Manifest?.Id ?? "?").EscapeMarkup()}[/]: {verdict}");
        var table = new Table().AddColumns("Field", "Signer", "Signed", "Valid", "Signer matches", "Level", "In order");
        foreach (var s in report.Signatures)
        {
            table.AddRow(
                s.Field.EscapeMarkup(),
                (s.Signer?.Name ?? "—").EscapeMarkup(),
                s.IsSigned ? "[green]✓[/]" : "[dim]no[/]",
                s.Validation?.Indication.ToString() ?? "—",
                !s.IsSigned ? "—" : s.SignerMatches ? "[green]✓[/]" : "[red]✗[/]",
                !s.IsSigned ? (s.Signer?.Level.Id ?? "—").EscapeMarkup() : s.LevelMet ? $"[green]✓[/] {(s.Signer?.Level.Id ?? "").EscapeMarkup()}" : $"[red]✗[/] {(s.Signer?.Level.Id ?? "").EscapeMarkup()}",
                !s.IsSigned ? "—" : s.InOrder ? "[green]✓[/]" : "[red]✗[/]");
        }

        AnsiConsole.Write(table);
        foreach (string problem in report.Envelope.Problems.Concat(report.Signatures.SelectMany(s => s.LevelProblems)))
        {
            AnsiConsole.MarkupLine($"[red]✗[/] {problem.EscapeMarkup()}");
        }

        return report.IsComplete ? 0 : 1;
    }
}
