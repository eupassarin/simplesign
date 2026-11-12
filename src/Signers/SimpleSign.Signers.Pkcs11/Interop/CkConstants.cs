namespace SimpleSign.Signers.Pkcs11.Interop;

/// <summary>PKCS#11 v2.40 constants used by this package (OASIS PKCS #11 Base Specification).</summary>
internal static class CkConstants
{
    // Return values (CK_RV)
    internal const ulong CkrOk = 0x000;
    internal const ulong CkrHostMemory = 0x002;
    internal const ulong CkrSlotIdInvalid = 0x003;
    internal const ulong CkrGeneralError = 0x005;
    internal const ulong CkrFunctionFailed = 0x006;
    internal const ulong CkrArgumentsBad = 0x007;
    internal const ulong CkrAttributeTypeInvalid = 0x012;
    internal const ulong CkrDataLenRange = 0x021;
    internal const ulong CkrDeviceError = 0x030;
    internal const ulong CkrDeviceMemory = 0x031;
    internal const ulong CkrDeviceRemoved = 0x032;
    internal const ulong CkrFunctionCanceled = 0x050;
    internal const ulong CkrFunctionNotSupported = 0x054;
    internal const ulong CkrKeyTypeInconsistent = 0x063;
    internal const ulong CkrKeyFunctionNotPermitted = 0x068;
    internal const ulong CkrMechanismInvalid = 0x070;
    internal const ulong CkrMechanismParamInvalid = 0x071;
    internal const ulong CkrObjectHandleInvalid = 0x082;
    internal const ulong CkrOperationActive = 0x090;
    internal const ulong CkrPinIncorrect = 0x0A0;
    internal const ulong CkrPinInvalid = 0x0A1;
    internal const ulong CkrPinLenRange = 0x0A2;
    internal const ulong CkrPinExpired = 0x0A3;
    internal const ulong CkrPinLocked = 0x0A4;
    internal const ulong CkrSessionCount = 0x0B1;
    internal const ulong CkrSessionHandleInvalid = 0x0B3;
    internal const ulong CkrTokenNotPresent = 0x0E0;
    internal const ulong CkrTokenNotRecognized = 0x0E1;
    internal const ulong CkrUserAlreadyLoggedIn = 0x100;
    internal const ulong CkrUserNotLoggedIn = 0x101;
    internal const ulong CkrUserTypeInvalid = 0x103;
    internal const ulong CkrBufferTooSmall = 0x150;
    internal const ulong CkrCryptokiNotInitialized = 0x190;
    internal const ulong CkrCryptokiAlreadyInitialized = 0x191;

    // Flags
    internal const ulong CkfRwSession = 0x2;
    internal const ulong CkfSerialSession = 0x4;
    internal const ulong CkfOsLockingOk = 0x2;
    internal const ulong CkfLoginRequired = 0x4;
    internal const ulong CkfUserPinInitialized = 0x8;
    internal const ulong CkfProtectedAuthenticationPath = 0x100;
    internal const ulong CkfTokenInitialized = 0x400;
    internal const ulong CkfUserPinCountLow = 0x10000;
    internal const ulong CkfUserPinFinalTry = 0x20000;
    internal const ulong CkfUserPinLocked = 0x40000;
    internal const ulong CkfUserPinToBeChanged = 0x80000;

    // User types
    internal const ulong CkuUser = 1;

    // Object classes and attribute types
    internal const ulong CkoCertificate = 1;
    internal const ulong CkoPrivateKey = 3;
    internal const ulong CkcX509 = 0;
    internal const ulong CkaClass = 0x000;
    internal const ulong CkaToken = 0x001;
    internal const ulong CkaLabel = 0x003;
    internal const ulong CkaValue = 0x011;
    internal const ulong CkaCertificateType = 0x080;
    internal const ulong CkaKeyType = 0x100;
    internal const ulong CkaId = 0x102;
    internal const ulong CkaSign = 0x108;
    internal const ulong CkkRsa = 0;
    internal const ulong CkkEc = 3;

    // Mechanisms
    internal const ulong CkmRsaPkcs = 0x0001;
    internal const ulong CkmRsaPkcsPss = 0x000D;
    internal const ulong CkmSha1 = 0x0220;
    internal const ulong CkmSha256 = 0x0250;
    internal const ulong CkmSha384 = 0x0260;
    internal const ulong CkmSha512 = 0x0270;
    internal const ulong CkmEcdsa = 0x1041;

    // Mask generation functions
    internal const ulong CkgMgf1Sha1 = 1;
    internal const ulong CkgMgf1Sha256 = 2;
    internal const ulong CkgMgf1Sha384 = 3;
    internal const ulong CkgMgf1Sha512 = 4;

    /// <summary>Returns the symbolic name of a CK_RV value, e.g. <c>CKR_PIN_INCORRECT</c>.</summary>
    internal static string ReturnValueName(ulong rv) => rv switch
    {
        CkrOk => "CKR_OK",
        CkrHostMemory => "CKR_HOST_MEMORY",
        CkrSlotIdInvalid => "CKR_SLOT_ID_INVALID",
        CkrGeneralError => "CKR_GENERAL_ERROR",
        CkrFunctionFailed => "CKR_FUNCTION_FAILED",
        CkrArgumentsBad => "CKR_ARGUMENTS_BAD",
        CkrAttributeTypeInvalid => "CKR_ATTRIBUTE_TYPE_INVALID",
        CkrDataLenRange => "CKR_DATA_LEN_RANGE",
        CkrDeviceError => "CKR_DEVICE_ERROR",
        CkrDeviceMemory => "CKR_DEVICE_MEMORY",
        CkrDeviceRemoved => "CKR_DEVICE_REMOVED",
        CkrFunctionCanceled => "CKR_FUNCTION_CANCELED",
        CkrFunctionNotSupported => "CKR_FUNCTION_NOT_SUPPORTED",
        CkrKeyTypeInconsistent => "CKR_KEY_TYPE_INCONSISTENT",
        CkrKeyFunctionNotPermitted => "CKR_KEY_FUNCTION_NOT_PERMITTED",
        CkrMechanismInvalid => "CKR_MECHANISM_INVALID",
        CkrMechanismParamInvalid => "CKR_MECHANISM_PARAM_INVALID",
        CkrObjectHandleInvalid => "CKR_OBJECT_HANDLE_INVALID",
        CkrOperationActive => "CKR_OPERATION_ACTIVE",
        CkrPinIncorrect => "CKR_PIN_INCORRECT",
        CkrPinInvalid => "CKR_PIN_INVALID",
        CkrPinLenRange => "CKR_PIN_LEN_RANGE",
        CkrPinExpired => "CKR_PIN_EXPIRED",
        CkrPinLocked => "CKR_PIN_LOCKED",
        CkrSessionCount => "CKR_SESSION_COUNT",
        CkrSessionHandleInvalid => "CKR_SESSION_HANDLE_INVALID",
        CkrTokenNotPresent => "CKR_TOKEN_NOT_PRESENT",
        CkrTokenNotRecognized => "CKR_TOKEN_NOT_RECOGNIZED",
        CkrUserAlreadyLoggedIn => "CKR_USER_ALREADY_LOGGED_IN",
        CkrUserNotLoggedIn => "CKR_USER_NOT_LOGGED_IN",
        CkrUserTypeInvalid => "CKR_USER_TYPE_INVALID",
        CkrBufferTooSmall => "CKR_BUFFER_TOO_SMALL",
        CkrCryptokiNotInitialized => "CKR_CRYPTOKI_NOT_INITIALIZED",
        CkrCryptokiAlreadyInitialized => "CKR_CRYPTOKI_ALREADY_INITIALIZED",
        _ => $"CKR_0x{rv:X8}",
    };

    /// <summary>Returns a short, user-facing explanation of the common CK_RV failures.</summary>
    internal static string Describe(ulong rv) => rv switch
    {
        CkrPinIncorrect => "The PIN is incorrect.",
        CkrPinInvalid or CkrPinLenRange => "The PIN has invalid characters or length.",
        CkrPinExpired => "The PIN has expired and must be changed with the token vendor's tool.",
        CkrPinLocked => "The PIN is locked after too many wrong attempts. Unlock it with the PUK in the token vendor's tool.",
        CkrTokenNotPresent or CkrDeviceRemoved => "The token is not connected.",
        CkrTokenNotRecognized => "The token was not recognized by the driver.",
        CkrUserNotLoggedIn => "The token requires a login (PIN) for this operation.",
        CkrMechanismInvalid or CkrMechanismParamInvalid => "The token does not support the requested signature algorithm.",
        CkrKeyTypeInconsistent => "The key type does not match the requested signature algorithm.",
        CkrKeyFunctionNotPermitted => "The key is not allowed to sign.",
        CkrFunctionCanceled => "The operation was canceled on the token (for example on the reader's PIN pad).",
        CkrSessionCount => "The token has no free sessions.",
        CkrDeviceError or CkrDeviceMemory => "The token reported a device error.",
        _ => "The PKCS#11 driver reported an error.",
    };
}
