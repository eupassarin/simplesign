using SimpleSign.Brasil.IcpBrasil;
using SimpleSign.Brasil.Signing;

namespace SimpleSign.Cli.Rendering;

/// <summary>Parses the ICP-Brasil options of <c>sign</c>: --icp-policy, --health-document, --registration.</summary>
internal static class IcpBrasilCliOptions
{
    internal static IcpBrasilPolicy? ParsePolicy(string? value) => value?.ToLowerInvariant() switch
    {
        "ad-rb" or "adrb" or "rb" => IcpBrasilPolicy.AdRb,
        "ad-rt" or "adrt" or "rt" => IcpBrasilPolicy.AdRt,
        _ => null,
    };

    internal static HealthDocumentType? ParseHealthDocument(string? value) => value?.ToLowerInvariant() switch
    {
        "prescricao" or "prescrição" or "prescription" => HealthDocumentType.Prescricao,
        "atestado" or "certificate" => HealthDocumentType.Atestado,
        "exame" or "solicitacao-exame" or "exam" => HealthDocumentType.SolicitacaoExame,
        "relatorio" or "relatório" or "report" => HealthDocumentType.Relatorio,
        _ => null,
    };

    /// <summary>Parses <c>COUNCIL:NUMBER[/UF]</c>, e.g. <c>crm:123456/SP</c> or <c>cff:9876/RJ</c>.</summary>
    internal static ProfessionalRegistration? ParseRegistration(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        int colon = value.IndexOf(':', StringComparison.Ordinal);
        if (colon <= 0 || colon == value.Length - 1)
        {
            return null;
        }

        var council = ParseCouncil(value[..colon]);
        string rest = value[(colon + 1)..];
        int slash = rest.IndexOf('/', StringComparison.Ordinal);
        string number = (slash >= 0 ? rest[..slash] : rest).Trim();
        string? uf = slash >= 0 ? rest[(slash + 1)..].Trim().ToUpperInvariant() : null;
        if (council is null || number.Length == 0 || uf is { Length: not 2 })
        {
            return null;
        }

        return new ProfessionalRegistration(council.Value, number, uf, null);
    }

    private static ProfessionalCouncil? ParseCouncil(string value) => value.Trim().ToLowerInvariant() switch
    {
        "oab" => ProfessionalCouncil.Oab,
        "crm" or "cfm" => ProfessionalCouncil.Cfm,
        "crf" or "cff" => ProfessionalCouncil.Cff,
        "crbio" or "cfbio" => ProfessionalCouncil.Cfbio,
        "crbm" or "cfbm" => ProfessionalCouncil.Cfbm,
        "cref" or "confef" => ProfessionalCouncil.Confef,
        "coren" or "cofen" => ProfessionalCouncil.Cofen,
        "crefito" or "coffito" => ProfessionalCouncil.Coffito,
        "crfa" or "cffa" => ProfessionalCouncil.Cffa,
        "crmv" or "cfmv" => ProfessionalCouncil.Cfmv,
        "crn" or "cfn" => ProfessionalCouncil.Cfn,
        "cro" or "cfo" => ProfessionalCouncil.Cfo,
        "crp" or "cfp" => ProfessionalCouncil.Cfp,
        "cress" or "cfess" => ProfessionalCouncil.Cfess,
        "crtr" or "conter" => ProfessionalCouncil.Conter,
        "crq" or "cfq" => ProfessionalCouncil.Cfq,
        _ => null,
    };
}
