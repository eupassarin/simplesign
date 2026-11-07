using System.Text.Json;
using SimpleSign.Cli.Json;
using SimpleSign.Core.Signing;

namespace SimpleSign.Cli.Commands;

/// <summary>
/// The <c>--json</c> output of <c>sign</c>, <c>cades sign</c> and <c>xades sign</c>: one JSON object on
/// stdout, for scripts and test runners. A refusal is written by the exception handler, also as JSON.
/// </summary>
internal static class SignJson
{
    /// <summary>Whether the running sign command asked for JSON (read by the exception handler).</summary>
    public static bool Enabled { get; set; }

    /// <summary>The baseline level as the CLI names it (B-B, B-T, B-LT, B-LTA).</summary>
    public static string Level(AdesBaselineLevel level) => level switch
    {
        AdesBaselineLevel.Basic => "B-B",
        AdesBaselineLevel.Timestamped => "B-T",
        AdesBaselineLevel.LongTerm => "B-LT",
        _ => "B-LTA",
    };

    /// <summary>Writes a successful signature.</summary>
    public static void WriteSuccess(string format, string output, string signer, ISigningResult result) =>
        Write(new SignOutput
        {
            Success = true,
            Format = format,
            Output = output,
            Signer = signer,
            RequestedLevel = Level(result.RequestedLevel),
            AchievedLevel = Level(result.AchievedLevel),
            Warnings = [.. result.Warnings.Select(w => w.Message)],
        });

    /// <summary>Writes a failure: the exception type, the SigningErrorReason when there is one, and the message.</summary>
    public static void WriteError(Exception exception) =>
        Write(new SignOutput
        {
            Success = false,
            Error = new SignErrorDto
            {
                Type = exception.GetType().Name,
                Reason = exception is SigningException signing ? signing.Reason.ToString() : null,
                Message = exception.Message,
            },
        });

    private static void Write(SignOutput output) =>
        Console.Out.WriteLine(JsonSerializer.Serialize(output, CliJsonContext.Default.SignOutput));
}
