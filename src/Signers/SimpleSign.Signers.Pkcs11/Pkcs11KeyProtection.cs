namespace SimpleSign.Signers.Pkcs11;

/// <summary>
/// How the token protects a private key, as its PKCS#11 driver reports it: the attributes of the key object and the
/// kind of slot the token is in. A value is <see langword="null"/> when the driver does not report it.
/// </summary>
/// <param name="Sensitive">Whether the key value cannot be read in plaintext (<c>CKA_SENSITIVE</c>).</param>
/// <param name="Extractable">Whether the key can be wrapped and taken out of the token (<c>CKA_EXTRACTABLE</c>).</param>
/// <param name="AlwaysSensitive">Whether the key has been sensitive since it was created (<c>CKA_ALWAYS_SENSITIVE</c>).</param>
/// <param name="NeverExtractable">Whether the key has never been extractable (<c>CKA_NEVER_EXTRACTABLE</c>).</param>
/// <param name="GeneratedOnToken">Whether the key was generated on the token, not imported (<c>CKA_LOCAL</c>).</param>
/// <param name="HardwareSlot">Whether the slot is a hardware device, not a software token (<c>CKF_HW_SLOT</c>).</param>
/// <remarks>
/// These are the driver's statements about the key: they say the key cannot leave the token, not that the token is
/// certified (FIPS 140-2, Common Criteria). A software token such as SoftHSM2 reports a sensitive, non-extractable key
/// too, with <see cref="HardwareSlot"/> false.
/// </remarks>
public sealed record Pkcs11KeyProtection(
    bool? Sensitive,
    bool? Extractable,
    bool? AlwaysSensitive,
    bool? NeverExtractable,
    bool? GeneratedOnToken,
    bool? HardwareSlot)
{
    /// <summary>
    /// Whether the driver states that the key value can neither be read nor taken out of the token: sensitive and not
    /// extractable. False when either attribute is not reported.
    /// </summary>
    public bool IsConfinedToToken => Sensitive == true && Extractable == false;
}
