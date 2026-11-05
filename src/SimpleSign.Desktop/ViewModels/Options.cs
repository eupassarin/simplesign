using SimpleSign.Brasil.IcpBrasil;
using SimpleSign.Desktop.Services;

namespace SimpleSign.Desktop.ViewModels;

/// <summary>The label of a choice, for templates.</summary>
internal abstract record OptionBase(string Label, string? Hint)
{
    public sealed override string ToString() => Label;
}

/// <summary>A labelled choice for segmented controls and pickers.</summary>
internal sealed record Option<T>(T Value, string Label, string? Hint = null) : OptionBase(Label, Hint);

internal static class Options
{
    public static IReadOnlyList<Option<SignatureFormat>> Formats { get; } =
    [
        new(SignatureFormat.Pades, "PDF (PAdES)", "Assinatura dentro do PDF"),
        new(SignatureFormat.CadesDetached, "CAdES .p7s", "Arquivo de assinatura separado"),
        new(SignatureFormat.CadesAttached, "CAdES .p7m", "Envelope com o conteúdo"),
        new(SignatureFormat.Xades, "XML (XAdES)", "Assinatura envelopada no XML"),
    ];

    public static IReadOnlyList<Option<SignatureLevel>> Levels { get; } =
    [
        new(SignatureLevel.Basic, "B-B", "Básica"),
        new(SignatureLevel.Timestamped, "B-T", "Com carimbo do tempo"),
        new(SignatureLevel.LongTerm, "B-LT", "Com dados de validação"),
        new(SignatureLevel.Archive, "B-LTA", "Com carimbo de arquivamento"),
    ];

    public static Option<IcpBrasilPolicy?> NoPolicy { get; } = new(null, "Sem política ICP-Brasil");

    public static IReadOnlyList<Option<IcpBrasilPolicy?>> Policies(SignatureFormat format) =>
        [NoPolicy, .. DocumentService.PoliciesFor(format).Select(p => new Option<IcpBrasilPolicy?>(p, PolicyName(p)))];

    public static string PolicyName(IcpBrasilPolicy policy) => policy switch
    {
        IcpBrasilPolicy.AdRb => "AD-RB · referência básica",
        IcpBrasilPolicy.AdRt => "AD-RT · com carimbo do tempo",
        IcpBrasilPolicy.AdRv => "AD-RV · referências para validação",
        IcpBrasilPolicy.AdRc => "AD-RC · referências completas",
        IcpBrasilPolicy.AdRa => "AD-RA · arquivamento",
        _ => policy.ToString(),
    };
}
