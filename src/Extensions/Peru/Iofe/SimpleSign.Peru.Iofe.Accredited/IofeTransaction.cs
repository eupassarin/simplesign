namespace SimpleSign.Peru.Iofe.Accredited;

/// <summary>
/// The transaction an automated agent signs for: its kind, which must be one of
/// <see cref="IofeSigningAgentOptions.Transactions"/>, and the identifier of this occurrence. Both go to the audit
/// record of the signature as <c>Type/Id</c> (guide Req. 14: an audit trail of the signatures by kind of transaction).
/// </summary>
/// <param name="Type">The kind of transaction (e.g. <c>factura</c>).</param>
/// <param name="Id">The identifier of this transaction in the system that asks for the signature.</param>
public sealed record IofeTransaction(string Type, string Id)
{
    /// <summary>The value written to the audit record: <c>Type/Id</c>.</summary>
    public string OperationId => $"{Type}/{Id}";
}
