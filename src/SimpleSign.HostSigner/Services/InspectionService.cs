using SimpleSign.PAdES.Inspection;

namespace SimpleSign.HostSigner.Services;

internal static class InspectionService
{
    public static async Task<InspectResultDto> InspectAsync(string path)
    {
        await using var stream = File.OpenRead(path);
        var result = await PdfSignatureInspector.InspectAsync(stream);
        return InspectMapper.Map(result);
    }
}
