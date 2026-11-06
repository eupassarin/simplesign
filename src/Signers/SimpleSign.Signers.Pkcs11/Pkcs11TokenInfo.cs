using System.Security.Cryptography.X509Certificates;

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
public sealed record Pkcs11TokenInfo(
    ulong SlotId,
    string Label,
    string Manufacturer,
    string Model,
    string SerialNumber,
    bool IsLoginRequired,
    bool HasProtectedAuthenticationPath,
    bool IsPinLocked,
    IReadOnlyList<Pkcs11CertificateInfo> Certificates);

/// <summary>A certificate stored on a token.</summary>
/// <param name="Label">The object label (CKA_LABEL), or <see langword="null"/>.</param>
/// <param name="Id">The object ID (CKA_ID) shared with its private key; may be empty.</param>
/// <param name="Certificate">The certificate. The caller owns it and should dispose it.</param>
public sealed record Pkcs11CertificateInfo(string? Label, ReadOnlyMemory<byte> Id, X509Certificate2 Certificate);
