namespace SimpleSign.Peru.Iofe.Accredited;

/// <summary>Why the accredited configuration refused an operation, beyond the checks of the signing policy.</summary>
public enum IofeRefusal
{
    /// <summary>No specific reason.</summary>
    Unspecified = 0,

    /// <summary>The driver does not state that the private key is sensitive and not extractable (guide Req. 15, 25).</summary>
    KeyNotInModule = 1,

    /// <summary>The token in use is not the cryptographic module the operator declared.</summary>
    ModuleMismatch = 2,

    /// <summary>The transaction is not one of those the signing agent was set up for (guide Req. 14).</summary>
    TransactionNotAllowed = 3,

    /// <summary>The options carry no audit sink (guide Req. 14, 24).</summary>
    AuditMissing = 4,

    /// <summary>The contingency the options declare is outside its validity (guide Req. 14, 24).</summary>
    ContingencyExpired = 5,

    /// <summary>The notice of a rejected document could not be handed to the notifier (guide section 4.3).</summary>
    NoticeNotDelivered = 6,

    /// <summary>
    /// The options are incomplete: no transactions, no notifier, no key source (a module or a remote service, one of
    /// the two) or no declaration of it.
    /// </summary>
    OptionsIncomplete = 7,

    /// <summary>The remote signing service in use is not the one the operator declared.</summary>
    RemoteServiceMismatch = 8,

    /// <summary>
    /// The credential of the remote service is authorized by a person (a login in a browser): an automated agent signs
    /// unattended (guide section 4.2).
    /// </summary>
    RemoteAuthorizationNotUnattended = 9,
}
