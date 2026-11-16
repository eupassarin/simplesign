using SimpleSign.PAdES.Pdf.Enums;

namespace SimpleSign.PAdES.Signing;

/// <summary>
/// Object numbers for the ICC profiles a signature stamp names as <c>/DefaultRGB</c> and <c>/DefaultGray</c>
/// on a PDF/A document (see <see cref="SignatureAppearanceRenderer.BuildAppearanceXObject"/>).
/// </summary>
/// <param name="RgbObjNum">Object number of the sRGB profile stream.</param>
/// <param name="GrayObjNum">Object number of the gray profile stream, written only when the stamp paints in DeviceGray.</param>
internal readonly record struct AppearanceColorProfiles(int RgbObjNum, int GrayObjNum)
{
    /// <summary>
    /// The profiles for a stamp whose form XObject is object <paramref name="appObjNum"/>, numbered after the objects
    /// the stamp already uses (image, font file, font descriptor, soft mask); <see langword="null"/> when the document
    /// is not PDF/A, which keeps DeviceRGB as it is.
    /// </summary>
    /// <param name="pdfALevel">PDF/A level of the document being signed (<see langword="null"/> when not detected).</param>
    /// <param name="appObjNum">Object number of the appearance form XObject.</param>
    internal static AppearanceColorProfiles? For(PdfALevel? pdfALevel, int appObjNum) =>
        pdfALevel is null or PdfALevel.None ? null : new AppearanceColorProfiles(appObjNum + 5, appObjNum + 6);
}
