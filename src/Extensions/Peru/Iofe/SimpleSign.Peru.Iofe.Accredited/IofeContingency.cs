namespace SimpleSign.Peru.Iofe.Accredited;

/// <summary>
/// A contingency declared by the operator, the one case in which the guide lets the checks of a certificate's status be
/// reduced (Req. 14, 24: "siempre activadas a menos que exista un caso de contingencia y se haya operado conforme a un
/// procedimiento aprobado por la AAC"). While it is in force the revocation is still asked for, and a signature is
/// made, or a document accepted, when the status cannot be obtained; a certificate known to be revoked or expired is
/// still refused. Its
/// <see cref="ProcedureReference"/> is part of the policy name of every audit record made under it.
/// </summary>
/// <param name="ProcedureReference">The procedure INDECOPI (the AAC) approved, as the operator's records name it.</param>
/// <param name="From">When the contingency starts.</param>
/// <param name="Until">When it ends; afterwards every operation is refused until the options no longer declare it.</param>
public sealed record IofeContingency(string ProcedureReference, DateTimeOffset From, DateTimeOffset Until)
{
    /// <summary>Whether the contingency is in force at <paramref name="time"/>.</summary>
    /// <param name="time">The time.</param>
    /// <returns>True from <see cref="From"/> to <see cref="Until"/>.</returns>
    public bool IsInForce(DateTimeOffset time) => time >= From && time <= Until;
}
