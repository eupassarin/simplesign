namespace SimpleSign.Brasil.GovBr;

/// <summary>Gov.br certificate security level.</summary>
public enum GovBrAssuranceLevel
{
    /// <summary>Level 1 — Bronze equivalent account (basic CPF validation)</summary>
    Level1 = 1,
    /// <summary>Level 2 — Silver equivalent account (biometrics or gov. database validation)</summary>
    Level2 = 2,
    /// <summary>Level 3 — Gold equivalent account (strong biometrics or accredited bank)</summary>
    Level3 = 3,
    /// <summary>Level 4 — Maximum assurance level</summary>
    Level4 = 4
}
