namespace SimpleSign.Brazil.Internal;

/// <summary>
/// Brazilian OID constants (arc 2.16.76.*), as assigned in the ITI's ADE-ICP-04.01
/// ("Esquema de OID na ICP-Brasil") and DOC-ICP-04.01.
/// </summary>
internal static class BrazilOids
{
    /// <summary>ICP-Brasil SAN otherName (PF): holder data — birth date (8), CPF (11), NIS (11), RG (15), issuer + UF (6).</summary>
    internal const string IcpBrasilSanHolderData = "2.16.76.1.3.1";

    /// <summary>ICP-Brasil SAN otherName (PJ): CNPJ of the legal entity (14 characters).</summary>
    internal const string IcpBrasilSanCnpj = "2.16.76.1.3.3";

    /// <summary>
    /// Arc of the professional councils ("Entidades de Classe"): 2.16.76.1.4.2.{council}, where
    /// .1 is the registration number, .2 the UF of the registration and .3 the specialty.
    /// </summary>
    internal const string ProfessionalCouncilArc = "2.16.76.1.4.2.";

    /// <summary>Arc of the digital health documents (2.16.76.1.12.1.n): 1 = prescription, 2 = medical certificate…</summary>
    internal const string HealthDocumentArc = "2.16.76.1.12.1.";
}
