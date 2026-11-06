namespace SimpleSign.Brasil.IcpBrasil;

/// <summary>Which ICP-Brasil hierarchy to trust.</summary>
public enum IcpBrasilEnvironment
{
    /// <summary>Only the production AC Raiz (the default).</summary>
    Production,

    /// <summary>
    /// The production AC Raiz plus the homologation (test) hierarchy used by SERPRO and the ACs
    /// to issue test certificates. Chains that end in a homologation root are reported as such
    /// (<see cref="IcpBrasilValidationResult.IsHomologation"/>) and never as qualified
    /// signatures. Do not use in production.
    /// </summary>
    Homologation,
}
