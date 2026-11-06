using SimpleSign.Core;
using SimpleSign.Signers.Pkcs11.Interop;

namespace SimpleSign.Signers.Pkcs11;

/// <summary>
/// A PKCS#11 driver call failed, or the token, key or certificate requested in
/// <see cref="Pkcs11SignerOptions"/> could not be found.
/// </summary>
public sealed class Pkcs11Exception : SimpleSignException
{
    /// <summary>Creates an exception for a failure that has no PKCS#11 return value.</summary>
    /// <param name="message">The error message.</param>
    public Pkcs11Exception(string message)
        : base(message)
    {
    }

    /// <summary>Creates an exception for a failure that has no PKCS#11 return value.</summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The underlying exception.</param>
    public Pkcs11Exception(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    internal Pkcs11Exception(string function, ulong returnValue)
        : base($"{function} failed with {CkConstants.ReturnValueName(returnValue)}: {CkConstants.Describe(returnValue)}")
    {
        Function = function;
        ReturnValue = returnValue;
    }

    /// <summary>The PKCS#11 function that failed (e.g. <c>C_Login</c>), or <see langword="null"/>.</summary>
    public string? Function { get; }

    /// <summary>The CK_RV returned by the driver, or <see langword="null"/> when no driver call failed.</summary>
    public ulong? ReturnValue { get; }

    /// <summary>The symbolic name of <see cref="ReturnValue"/> (e.g. <c>CKR_PIN_INCORRECT</c>), or <see langword="null"/>.</summary>
    public string? ReturnValueName => ReturnValue is { } rv ? CkConstants.ReturnValueName(rv) : null;

    /// <summary>Whether the failure was a wrong PIN (<c>CKR_PIN_INCORRECT</c>).</summary>
    public bool IsPinIncorrect => ReturnValue == CkConstants.CkrPinIncorrect;

    /// <summary>Whether the PIN is locked (<c>CKR_PIN_LOCKED</c>).</summary>
    public bool IsPinLocked => ReturnValue == CkConstants.CkrPinLocked;
}
