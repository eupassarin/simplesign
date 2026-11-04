namespace SimpleSign.Brasil.IcpBrasil;

/// <summary>
/// Brazilian professional councils ("Entidades de Classe") with an ICP-Brasil OID arc
/// 2.16.76.1.4.2.{n} (ADE-ICP-04.01). The enum value is the council's arc number.
/// </summary>
public enum ProfessionalCouncil
{
    /// <summary>OAB — Ordem dos Advogados do Brasil (2.16.76.1.4.2.1).</summary>
    Oab = 1,

    /// <summary>CFM — Conselho Federal de Medicina (2.16.76.1.4.2.2).</summary>
    Cfm = 2,

    /// <summary>CFF — Conselho Federal de Farmácia (2.16.76.1.4.2.3).</summary>
    Cff = 3,

    /// <summary>CFBio — Conselho Federal de Biologia (2.16.76.1.4.2.4).</summary>
    Cfbio = 4,

    /// <summary>CFBM — Conselho Federal de Biomedicina (2.16.76.1.4.2.5).</summary>
    Cfbm = 5,

    /// <summary>CONFEF — Conselho Federal de Educação Física (2.16.76.1.4.2.6).</summary>
    Confef = 6,

    /// <summary>COFEN — Conselho Federal de Enfermagem (2.16.76.1.4.2.7).</summary>
    Cofen = 7,

    /// <summary>COFFITO — Conselho Federal de Fisioterapia e Terapia Ocupacional (2.16.76.1.4.2.8).</summary>
    Coffito = 8,

    /// <summary>CFFa — Conselho Federal de Fonoaudiologia (2.16.76.1.4.2.9).</summary>
    Cffa = 9,

    /// <summary>CFMV — Conselho Federal de Medicina Veterinária (2.16.76.1.4.2.10).</summary>
    Cfmv = 10,

    /// <summary>CFN — Conselho Federal de Nutricionistas (2.16.76.1.4.2.11).</summary>
    Cfn = 11,

    /// <summary>CFO — Conselho Federal de Odontologia (2.16.76.1.4.2.12).</summary>
    Cfo = 12,

    /// <summary>CFP — Conselho Federal de Psicologia (2.16.76.1.4.2.13).</summary>
    Cfp = 13,

    /// <summary>CFESS — Conselho Federal de Serviço Social (2.16.76.1.4.2.14).</summary>
    Cfess = 14,

    /// <summary>CONTER — Conselho Nacional de Técnicos em Radiologia (2.16.76.1.4.2.15).</summary>
    Conter = 15,

    /// <summary>CFQ — Conselho Federal de Química (2.16.76.1.4.2.16).</summary>
    Cfq = 16,
}

/// <summary>
/// A professional registration carried in an ICP-Brasil certificate's SubjectAltName, under the
/// council arc 2.16.76.1.4.2.{council}: registration number (.1), UF (.2) and specialty (.3).
/// </summary>
/// <param name="Council">The council that issued the registration.</param>
/// <param name="RegistrationNumber">The registration number, as encoded in the certificate.</param>
/// <param name="StateCode">The UF of the registration (e.g. "SP"), when present.</param>
/// <param name="Specialty">The specialty, when present.</param>
public sealed record ProfessionalRegistration(
    ProfessionalCouncil Council,
    string RegistrationNumber,
    string? StateCode,
    string? Specialty);
