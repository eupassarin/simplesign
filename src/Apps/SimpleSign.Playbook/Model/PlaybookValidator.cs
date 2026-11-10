using System.Text.Json;
using System.Text.RegularExpressions;

namespace SimpleSign.Playbook.Model;

/// <summary>A problem in a playbook: where (a JSON path such as sections[0].steps[2].run) and what.</summary>
public sealed record PlaybookIssue(string Path, string Message, bool IsError = true);

/// <summary>Reads a playbook and checks it before it runs.</summary>
public static partial class PlaybookValidator
{
    /// <summary>The Sandbox actions a step can use.</summary>
    public static readonly IReadOnlyList<string> SandboxActions = ["faults", "revoke", "unrevoke", "reset", "certificate", "shortLived"];

    private static readonly string[] s_crlFaults = ["None", "Down", "Slow", "Expired", "WrongKey", "Stale"];
    private static readonly string[] s_ocspFaults = ["None", "Down", "Slow", "TryLater", "Expired", "Unauthorized", "Unknown"];
    private static readonly string[] s_tsaFaults = ["None", "Down", "Slow", "InvalidToken"];
    private static readonly string[] s_ocspSigners = ["Issuer", "Delegated"];
    private static readonly string[] s_tlFaults = ["None", "Expired", "WrongSigner", "Tampered"];
    private static readonly string[] s_publications = ["Both", "CrlOnly", "OcspOnly"];

    /// <summary>Parses <paramref name="json"/>; a syntax error is one issue at its line and column.</summary>
    public static (PlaybookDefinition? Playbook, IReadOnlyList<PlaybookIssue> Issues) Parse(string json)
    {
        try
        {
            var playbook = JsonSerializer.Deserialize(json, PlaybookJson.Default.PlaybookDefinition);
            return playbook is null
                ? (null, [new PlaybookIssue("", "The file is empty.")])
                : (playbook, Validate(playbook));
        }
        catch (JsonException ex)
        {
            string where = ex.LineNumber is { } line ? $"line {line + 1}, column {(ex.BytePositionInLine ?? 0) + 1}" : "";
            return (null, [new PlaybookIssue(ex.Path ?? "", $"Not a valid playbook ({where}): {ex.Message}")]);
        }
    }

    /// <summary>Checks a parsed playbook. Errors stop a run; warnings do not.</summary>
    /// <param name="playbook">The playbook.</param>
    /// <param name="workspace">When given, asset files are checked to exist in it.</param>
    public static IReadOnlyList<PlaybookIssue> Validate(PlaybookDefinition playbook, string? workspace = null)
    {
        ArgumentNullException.ThrowIfNull(playbook);
        var issues = new List<PlaybookIssue>();
        void Error(string path, string message) => issues.Add(new PlaybookIssue(path, message));
        void Warn(string path, string message) => issues.Add(new PlaybookIssue(path, message, IsError: false));

        if (playbook.Schema != PlaybookDefinition.CurrentSchema)
        {
            Error("schema", $"Unknown schema {playbook.Schema}; this version reads schema {PlaybookDefinition.CurrentSchema}.");
        }

        if (string.IsNullOrWhiteSpace(playbook.Name))
        {
            Error("name", "The playbook needs a name.");
        }

        if (playbook.Sandbox is { } sandbox && !Uri.TryCreate(sandbox.Url, UriKind.Absolute, out _))
        {
            Error("sandbox.url", $"'{sandbox.Url}' is not an absolute URL.");
        }

        var assetIds = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 0; i < playbook.Assets.Count; i++)
        {
            var asset = playbook.Assets[i];
            string path = $"assets[{i}]";
            if (!IsId(asset.Id))
            {
                Error($"{path}.id", "An asset id uses letters, digits, '-' and '_' only.");
            }
            else if (!assetIds.Add(asset.Id))
            {
                Error($"{path}.id", $"Asset '{asset.Id}' is defined twice.");
            }

            if (string.IsNullOrWhiteSpace(asset.File))
            {
                Error($"{path}.file", "The asset needs a file.");
            }
            else if (Path.IsPathRooted(asset.File) || asset.File.Split('/', '\\').Contains(".."))
            {
                Error($"{path}.file", "The file must be inside the workspace (a relative path, no '..').");
            }
            else if (workspace is not null && !File.Exists(Path.Combine(workspace, asset.File)))
            {
                Warn($"{path}.file", $"The file '{asset.File}' is not in the workspace yet.");
            }
        }

        var sectionIds = new HashSet<string>(StringComparer.Ordinal);
        var stepIds = new HashSet<string>(StringComparer.Ordinal);
        if (playbook.Sections.Count == 0)
        {
            Warn("sections", "The playbook has no steps yet.");
        }

        for (int s = 0; s < playbook.Sections.Count; s++)
        {
            var section = playbook.Sections[s];
            string sectionPath = $"sections[{s}]";
            if (!IsId(section.Id))
            {
                Error($"{sectionPath}.id", "A section id uses letters, digits, '-' and '_' only.");
            }
            else if (!sectionIds.Add(section.Id))
            {
                Error($"{sectionPath}.id", $"Section '{section.Id}' is defined twice.");
            }

            for (int t = 0; t < section.Steps.Count; t++)
            {
                var step = section.Steps[t];
                string path = $"{sectionPath}.steps[{t}]";
                if (!IsId(step.Id))
                {
                    Error($"{path}.id", "A step id uses letters, digits, '-' and '_' only.");
                }
                else if (!stepIds.Add(step.Id))
                {
                    Error($"{path}.id", $"Step '{step.Id}' is defined twice (step ids are unique in the playbook).");
                }

                if (string.IsNullOrWhiteSpace(step.Title))
                {
                    Warn($"{path}.title", "The step has no title.");
                }

                if (step.Manual)
                {
                    if (step.Run is not null)
                    {
                        Warn($"{path}.run", "A manual step does not run a command; run is ignored.");
                    }
                }
                else if (step.Run is null || step.Run.Args.Count == 0)
                {
                    Error($"{path}.run.args", "The step needs a command (run.args), or manual: true.");
                }
                else
                {
                    if (step.Run.TimeoutSeconds is < 1 or > 3600)
                    {
                        Error($"{path}.run.timeoutSeconds", "The timeout is between 1 and 3600 seconds.");
                    }

                    if (step.Run.Network is not (null or "sandbox" or "none"))
                    {
                        Error($"{path}.run.network", "network is \"sandbox\" or \"none\".");
                    }
                }

                CheckActions(step.Setup, $"{path}.setup", playbook.Sandbox is not null, Error);
                CheckActions(step.Teardown, $"{path}.teardown", playbook.Sandbox is not null, Error);
                if (step.Expect is { } expect)
                {
                    for (int r = 0; r < expect.StdoutMatches.Count; r++)
                    {
                        try
                        {
                            _ = new Regex(expect.StdoutMatches[r], RegexOptions.None, TimeSpan.FromSeconds(1));
                        }
                        catch (ArgumentException ex)
                        {
                            Error($"{path}.expect.stdoutMatches[{r}]", $"Not a regular expression: {ex.Message}");
                        }
                    }

                    if (expect.SandboxRequests.Count > 0 && playbook.Sandbox is null)
                    {
                        Error($"{path}.expect.sandboxRequests", "Checking the Sandbox's requests needs a sandbox in the playbook.");
                    }
                }
            }
        }

        return issues;
    }

    private static void CheckActions(List<SandboxAction> actions, string path, bool hasSandbox, Action<string, string> error)
    {
        for (int i = 0; i < actions.Count; i++)
        {
            var action = actions[i];
            string at = $"{path}[{i}]";
            if (!hasSandbox)
            {
                error(at, "Sandbox actions need a sandbox in the playbook.");
                return;
            }

            if (!SandboxActions.Contains(action.Sandbox))
            {
                error($"{at}.sandbox", $"Unknown action '{action.Sandbox}' ({string.Join(", ", SandboxActions)}).");
                continue;
            }

            switch (action.Sandbox)
            {
                case "revoke" or "unrevoke" when string.IsNullOrWhiteSpace(action.Certificate):
                    error($"{at}.certificate", $"{action.Sandbox} needs the certificate's id.");
                    break;
                case "revoke" when action.Publication is { } publication && !s_publications.Contains(publication):
                    error($"{at}.publication", $"publication is {string.Join(", ", s_publications)}.");
                    break;
                case "certificate" when string.IsNullOrWhiteSpace(action.Id):
                    error($"{at}.id", "certificate needs the certificate's id.");
                    break;
                case "shortLived" when action.Seconds is not (null or (>= 1 and <= 3600)):
                    error($"{at}.seconds", "seconds is between 1 and 3600.");
                    break;
                case "faults":
                    Check(action.Crl, s_crlFaults, $"{at}.crl", error);
                    Check(action.Ocsp, s_ocspFaults, $"{at}.ocsp", error);
                    Check(action.Tsa, s_tsaFaults, $"{at}.tsa", error);
                    Check(action.OcspSigner, s_ocspSigners, $"{at}.ocspSigner", error);
                    Check(action.TrustedList, s_tlFaults, $"{at}.trustedList", error);
                    break;
                default:
                    break;
            }

            if (action.As is { } name && !IsId(name))
            {
                error($"{at}.as", "The variable name uses letters, digits, '-' and '_' only.");
            }
        }
    }

    private static void Check(string? value, string[] allowed, string path, Action<string, string> error)
    {
        if (value is not null && !allowed.Contains(value))
        {
            error(path, $"'{value}' is not one of {string.Join(", ", allowed)}.");
        }
    }

    /// <summary>Whether <paramref name="value"/> is a usable id (letters, digits, '-', '_').</summary>
    public static bool IsId(string? value) => !string.IsNullOrEmpty(value) && IdPattern().IsMatch(value);

    [GeneratedRegex("^[A-Za-z0-9_-]+$")]
    private static partial Regex IdPattern();
}
