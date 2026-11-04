using System.Security.Cryptography.X509Certificates;

namespace SimpleSign.Signers.Pkcs11;

/// <summary>
/// Selects the PKCS#11 driver, the token and the signing key for <see cref="Pkcs11Signer.Open"/>.
/// Every selector is optional: with none, the only token present and its only key that has a
/// certificate are used.
/// </summary>
public sealed record Pkcs11SignerOptions
{
    /// <summary>
    /// Path or name of the token vendor's PKCS#11 library, e.g. <c>/usr/lib/libaetpkss.so</c>
    /// (SafeNet), <c>/usr/lib/libwdpkcs.so</c> (Watchdata) or <c>C:\Windows\System32\eTPKCS11.dll</c>.
    /// </summary>
    public required string LibraryPath { get; init; }

    /// <summary>Selects the token by its label (CK_TOKEN_INFO.label).</summary>
    public string? TokenLabel { get; init; }

    /// <summary>Selects the token by its serial number (CK_TOKEN_INFO.serialNumber).</summary>
    public string? TokenSerial { get; init; }

    /// <summary>Selects the token by the ID of the slot (reader) it is in.</summary>
    public ulong? SlotId { get; init; }

    /// <summary>Selects the key by the label of the key or of its certificate (CKA_LABEL).</summary>
    public string? KeyLabel { get; init; }

    /// <summary>Selects the key by its ID (CKA_ID), shared by the key and its certificate.</summary>
    public ReadOnlyMemory<byte>? KeyId { get; init; }

    /// <summary>
    /// The user PIN. Leave <see langword="null"/> for readers with a PIN pad (protected
    /// authentication path), where the PIN is typed on the reader.
    /// </summary>
    /// <remarks>The PIN is copied to a native buffer that is zeroed right after login, and it is never logged.</remarks>
    public string? Pin { get; init; }

    /// <summary>
    /// Selects the key by its certificate's thumbprint (SHA-1 hex, case-insensitive), as shown by
    /// <see cref="Pkcs11Signer.ListTokens"/> and <see cref="X509Certificate2.Thumbprint"/>.
    /// </summary>
    public string? CertificateThumbprint { get; init; }
}
