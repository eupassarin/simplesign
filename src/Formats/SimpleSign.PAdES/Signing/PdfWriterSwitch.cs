namespace SimpleSign.PAdES.Signing;

/// <summary>
/// The switch back to the writers before the PDF object model (ADR 0032), for one preview: with
/// <c>AppContext.SetSwitch("SimpleSign.PAdES.UseLegacyPdfWriter", true)</c> (or the same name in
/// <c>runtimeconfig.json</c>), the signer, the document timestamp writer and the LTV embedder write as they did,
/// finding the objects they update by searching the file's text.
/// </summary>
internal static class PdfWriterSwitch
{
    /// <summary>The switch's name.</summary>
    public const string Name = "SimpleSign.PAdES.UseLegacyPdfWriter";

    /// <summary>Whether the legacy writers are used.</summary>
    public static bool UseLegacy => AppContext.TryGetSwitch(Name, out bool enabled) && enabled;
}
