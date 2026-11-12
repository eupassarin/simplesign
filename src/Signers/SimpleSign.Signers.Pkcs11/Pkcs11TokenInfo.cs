using System.Security.Cryptography.X509Certificates;
using SimpleSign.Signers.Pkcs11.Interop;

namespace SimpleSign.Signers.Pkcs11;

/// <summary>A token found by <see cref="Pkcs11Signer.ListTokens"/>.</summary>
/// <param name="SlotId">The ID of the slot (reader) the token is in.</param>
/// <param name="Label">The token label.</param>
/// <param name="Manufacturer">The token manufacturer.</param>
/// <param name="Model">The token model.</param>
/// <param name="SerialNumber">The token serial number.</param>
/// <param name="IsLoginRequired">Whether a PIN is needed to use the private keys.</param>
/// <param name="HasProtectedAuthenticationPath">Whether the PIN is typed on the reader (PIN pad).</param>
/// <param name="IsPinLocked">Whether the user PIN is locked.</param>
/// <param name="Certificates">The X.509 certificates stored on the token (readable without a PIN).</param>
/// <remarks>
/// The PIN flags come from <c>CK_TOKEN_INFO.flags</c> as the driver reports them: show a warning before asking for the
/// PIN when <see cref="IsPinCountLow"/> or <see cref="IsPinFinalTry"/> is set, since one more wrong PIN may lock the
/// token. Drivers that do not count attempts never set them.
/// </remarks>
public sealed record Pkcs11TokenInfo(
    ulong SlotId,
    string Label,
    string Manufacturer,
    string Model,
    string SerialNumber,
    bool IsLoginRequired,
    bool HasProtectedAuthenticationPath,
    bool IsPinLocked,
    IReadOnlyList<Pkcs11CertificateInfo> Certificates)
{
    /// <summary>Whether a wrong user PIN was typed since the last good one (<c>CKF_USER_PIN_COUNT_LOW</c>).</summary>
    public bool IsPinCountLow { get; init; }

    /// <summary>Whether one more wrong user PIN locks it (<c>CKF_USER_PIN_FINAL_TRY</c>).</summary>
    public bool IsPinFinalTry { get; init; }

    /// <summary>
    /// Whether the user PIN is still the one set at initialization or by the issuer and must be changed before use
    /// (<c>CKF_USER_PIN_TO_BE_CHANGED</c>).
    /// </summary>
    public bool IsPinToBeChanged { get; init; }

    /// <summary>Whether the user PIN has been set (<c>CKF_USER_PIN_INITIALIZED</c>).</summary>
    public bool IsUserPinInitialized { get; init; }

    /// <summary>The token's flags (<c>CK_TOKEN_INFO.flags</c>) mapped onto the properties of the record.</summary>
    internal static Pkcs11TokenInfo FromFlags(
        ulong slotId, string label, string manufacturer, string model, string serialNumber, ulong flags,
        IReadOnlyList<Pkcs11CertificateInfo> certificates) =>
        new(slotId, label, manufacturer, model, serialNumber,
            IsLoginRequired: (flags & CkConstants.CkfLoginRequired) != 0,
            HasProtectedAuthenticationPath: (flags & CkConstants.CkfProtectedAuthenticationPath) != 0,
            IsPinLocked: (flags & CkConstants.CkfUserPinLocked) != 0,
            certificates)
        {
            IsPinCountLow = (flags & CkConstants.CkfUserPinCountLow) != 0,
            IsPinFinalTry = (flags & CkConstants.CkfUserPinFinalTry) != 0,
            IsPinToBeChanged = (flags & CkConstants.CkfUserPinToBeChanged) != 0,
            IsUserPinInitialized = (flags & CkConstants.CkfUserPinInitialized) != 0,
        };
}

/// <summary>A certificate stored on a token.</summary>
/// <param name="Label">The object label (CKA_LABEL), or <see langword="null"/>.</param>
/// <param name="Id">The object ID (CKA_ID) shared with its private key; may be empty.</param>
/// <param name="Certificate">The certificate. The caller owns it and should dispose it.</param>
public sealed record Pkcs11CertificateInfo(string? Label, ReadOnlyMemory<byte> Id, X509Certificate2 Certificate);
