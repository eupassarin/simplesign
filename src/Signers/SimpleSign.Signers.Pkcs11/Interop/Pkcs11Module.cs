using System.Runtime.InteropServices;
using System.Text;

namespace SimpleSign.Signers.Pkcs11.Interop;

/// <summary>Raw token information read from CK_TOKEN_INFO.</summary>
internal sealed record CkTokenInfo(string Label, string Manufacturer, string Model, string SerialNumber, ulong Flags);

/// <summary>
/// A loaded PKCS#11 module (driver library). One instance exists per library path in the
/// process; it is initialized (C_Initialize) for its first user and finalized (C_Finalize) when
/// the last one releases it, and initialized again for the next user.
/// </summary>
/// <remarks>
/// <para>
/// Functions are called through delegates over the pointers in CK_FUNCTION_LIST. Every delegate
/// takes only <see cref="nint"/>, <see cref="nuint"/> and <see cref="byte"/> arguments, so the
/// calls are blittable: no <c>unsafe</c> code and no runtime marshalling.
/// </para>
/// <para>
/// A driver stays loaded until the process ends: it is never unloaded once C_GetFunctionList was
/// found. A driver, or a library it brings with it (OpenSSL's libcrypto in SoftHSM2 and OpenSC),
/// leaves per-thread state behind whose cleanup runs when a thread that called it exits; with the
/// library unmapped that cleanup jumps to an address that no longer exists and the process dies
/// (SIGSEGV in <c>_pthread_exit</c> on macOS). The threads are the caller's (thread pool, test
/// runner), so there is no moment at which unloading is known to be safe.
/// </para>
/// </remarks>
internal sealed class Pkcs11Module
{
    private static readonly Dictionary<string, Pkcs11Module> Modules = new(StringComparer.Ordinal);
#if NET9_0_OR_GREATER
    private static readonly Lock ModulesGate = new();
#else
    private static readonly object ModulesGate = new();
#endif

    // Indexes in CK_FUNCTION_LIST (PKCS#11 v2.40, counted from C_Initialize).
    private const int IndexInitialize = 0;
    private const int IndexFinalize = 1;
    private const int IndexGetSlotList = 4;
    private const int IndexGetSlotInfo = 5;
    private const int IndexGetTokenInfo = 6;
    private const int IndexOpenSession = 12;
    private const int IndexCloseSession = 13;
    private const int IndexLogin = 18;
    private const int IndexLogout = 19;
    private const int IndexGetAttributeValue = 24;
    private const int IndexFindObjectsInit = 26;
    private const int IndexFindObjects = 27;
    private const int IndexFindObjectsFinal = 28;
    private const int IndexSignInit = 42;
    private const int IndexSign = 43;

    private bool _initializedByUs;
    private readonly CInitialize _initialize;
    private readonly CFinalize _finalize;
    private readonly CGetSlotList _getSlotList;
    private readonly CGetSlotInfo _getSlotInfo;
    private readonly CGetTokenInfo _getTokenInfo;
    private readonly COpenSession _openSession;
    private readonly CCloseSession _closeSession;
    private readonly CLogin _login;
    private readonly CLogout _logout;
    private readonly CGetAttributeValue _getAttributeValue;
    private readonly CFindObjectsInit _findObjectsInit;
    private readonly CFindObjects _findObjects;
    private readonly CFindObjectsFinal _findObjectsFinal;
    private readonly CSignInit _signInit;
    private readonly CSign _sign;
    private int _references;

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nuint CGetFunctionList(nint functionList);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nuint CInitialize(nint initArgs);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nuint CFinalize(nint reserved);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nuint CGetSlotList(byte tokenPresent, nint slotList, nint count);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nuint CGetSlotInfo(nuint slotId, nint info);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nuint CGetTokenInfo(nuint slotId, nint info);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nuint COpenSession(nuint slotId, nuint flags, nint application, nint notify, nint session);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nuint CCloseSession(nuint session);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nuint CLogin(nuint session, nuint userType, nint pin, nuint pinLength);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nuint CLogout(nuint session);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nuint CGetAttributeValue(nuint session, nuint objectHandle, nint template, nuint count);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nuint CFindObjectsInit(nuint session, nint template, nuint count);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nuint CFindObjects(nuint session, nint objects, nuint maxCount, nint count);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nuint CFindObjectsFinal(nuint session);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nuint CSignInit(nuint session, nint mechanism, nuint key);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate nuint CSign(nuint session, nint data, nuint dataLength, nint signature, nint signatureLength);

    private Pkcs11Module(nint library, CkLayout layout)
    {
        Layout = layout;

        var getFunctionList = Marshal.GetDelegateForFunctionPointer<CGetFunctionList>(
            NativeLibrary.GetExport(library, "C_GetFunctionList"));
        nint functionList;
        using (var memory = new NativeAllocations())
        {
            nint slot = memory.Allocate(layout.PointerSize);
            Check("C_GetFunctionList", layout.Normalize(getFunctionList(slot)));
            functionList = layout.ReadPointer(slot, 0);
        }

        if (functionList == 0)
        {
            throw new Pkcs11Exception("The PKCS#11 library returned an empty function list.");
        }

        _initialize = Function<CInitialize>(functionList, IndexInitialize);
        _finalize = Function<CFinalize>(functionList, IndexFinalize);
        _getSlotList = Function<CGetSlotList>(functionList, IndexGetSlotList);
        _getSlotInfo = Function<CGetSlotInfo>(functionList, IndexGetSlotInfo);
        _getTokenInfo = Function<CGetTokenInfo>(functionList, IndexGetTokenInfo);
        _openSession = Function<COpenSession>(functionList, IndexOpenSession);
        _closeSession = Function<CCloseSession>(functionList, IndexCloseSession);
        _login = Function<CLogin>(functionList, IndexLogin);
        _logout = Function<CLogout>(functionList, IndexLogout);
        _getAttributeValue = Function<CGetAttributeValue>(functionList, IndexGetAttributeValue);
        _findObjectsInit = Function<CFindObjectsInit>(functionList, IndexFindObjectsInit);
        _findObjects = Function<CFindObjects>(functionList, IndexFindObjects);
        _findObjectsFinal = Function<CFindObjectsFinal>(functionList, IndexFindObjectsFinal);
        _signInit = Function<CSignInit>(functionList, IndexSignInit);
        _sign = Function<CSign>(functionList, IndexSign);
    }

    /// <summary>The structure layout of this process.</summary>
    internal CkLayout Layout { get; }

    /// <summary>Whether the driver at <paramref name="libraryPath"/> is loaded in this process (in use or not).</summary>
    internal static bool IsLoaded(string libraryPath)
    {
        lock (ModulesGate)
        {
            return Modules.ContainsKey(Key(libraryPath));
        }
    }

    /// <summary>
    /// Loads the module at <paramref name="libraryPath"/>, or reuses the one already loaded, and
    /// adds a reference. The first reference initializes the module.
    /// </summary>
    /// <exception cref="Pkcs11Exception">The library cannot be loaded or initialized.</exception>
    internal static Pkcs11Module Acquire(string libraryPath)
    {
        string key = Key(libraryPath);
        lock (ModulesGate)
        {
            if (!Modules.TryGetValue(key, out var module))
            {
                nint library;
                try
                {
                    library = NativeLibrary.Load(key);
                }
                catch (DllNotFoundException ex)
                {
                    throw new Pkcs11Exception($"The PKCS#11 library '{libraryPath}' could not be loaded.", ex);
                }
                catch (BadImageFormatException ex)
                {
                    throw new Pkcs11Exception(
                        $"The PKCS#11 library '{libraryPath}' is not a library for this process architecture.", ex);
                }

                try
                {
                    module = new Pkcs11Module(library, CkLayout.Current);
                }
                catch (EntryPointNotFoundException ex)
                {
                    // Not a driver, and none of its functions was called: the only case that unloads.
                    NativeLibrary.Free(library);
                    throw new Pkcs11Exception($"'{libraryPath}' is not a PKCS#11 library (no C_GetFunctionList).", ex);
                }

                Modules[key] = module;
            }

            if (module._references == 0)
            {
                // A module whose C_Initialize fails stays loaded and is initialized again on the next call.
                module.Initialize();
            }

            module._references++;
            return module;
        }
    }

    /// <summary>
    /// Removes a reference; the last one finalizes the module (when this class initialized it).
    /// The library stays loaded, see the remarks of <see cref="Pkcs11Module"/>.
    /// </summary>
    internal void Release()
    {
        lock (ModulesGate)
        {
            if (--_references > 0)
            {
                return;
            }

            if (_initializedByUs)
            {
                _initializedByUs = false;
                _ = _finalize(0);
            }
        }
    }

    /// <summary>Returns the IDs of the slots that have a token present.</summary>
    internal IReadOnlyList<ulong> GetSlotsWithToken()
    {
        using var memory = new NativeAllocations();
        nint count = memory.Allocate(Layout.ULongSize);
        Check("C_GetSlotList", Layout.Normalize(_getSlotList(1, 0, count)));
        int slotCount = checked((int)Layout.ReadULong(count, 0));
        if (slotCount == 0)
        {
            return [];
        }

        nint slots = memory.Allocate(slotCount * Layout.ULongSize);
        Check("C_GetSlotList", Layout.Normalize(_getSlotList(1, slots, count)));
        slotCount = checked((int)Layout.ReadULong(count, 0));

        var result = new List<ulong>(slotCount);
        for (int i = 0; i < slotCount; i++)
        {
            result.Add(Layout.ReadULong(slots, i * Layout.ULongSize));
        }

        return result;
    }

    /// <summary>Reads the flags of CK_SLOT_INFO for a slot, or <see langword="null"/> when the driver does not report them.</summary>
    internal ulong? GetSlotFlags(ulong slotId)
    {
        using var memory = new NativeAllocations();
        nint info = memory.Allocate(CkLayout.SlotInfoBufferSize);
        return Layout.Normalize(_getSlotInfo((nuint)slotId, info)) == CkConstants.CkrOk
            ? Layout.ReadULong(info, CkLayout.SlotInfoFlagsOffset)
            : null;
    }

    /// <summary>Reads a CK_BBOOL attribute, or <see langword="null"/> when the object does not report it.</summary>
    internal bool? GetBooleanAttribute(ulong session, ulong objectHandle, ulong type) =>
        GetAttribute(session, objectHandle, type) is { Length: > 0 } value ? value[0] != 0 : null;

    /// <summary>Reads CK_TOKEN_INFO for a slot.</summary>
    internal CkTokenInfo GetTokenInfo(ulong slotId)
    {
        using var memory = new NativeAllocations();
        nint info = memory.Allocate(CkLayout.TokenInfoBufferSize);
        Check("C_GetTokenInfo", Layout.Normalize(_getTokenInfo((nuint)slotId, info)));
        byte[] text = NativeAllocations.Read(info, CkLayout.TokenInfoFlagsOffset);
        return new CkTokenInfo(
            Label: PaddedText(text, 0, 32),
            Manufacturer: PaddedText(text, 32, 32),
            Model: PaddedText(text, 64, 16),
            SerialNumber: PaddedText(text, 80, 16),
            Flags: Layout.ReadULong(info, CkLayout.TokenInfoFlagsOffset));
    }

    /// <summary>Opens a read-only serial session.</summary>
    internal ulong OpenSession(ulong slotId)
    {
        using var memory = new NativeAllocations();
        nint session = memory.Allocate(Layout.ULongSize);
        Check("C_OpenSession", Layout.Normalize(
            _openSession((nuint)slotId, (nuint)CkConstants.CkfSerialSession, 0, 0, session)));
        return Layout.ReadULong(session, 0);
    }

    /// <summary>Closes a session, ignoring errors (used on cleanup paths).</summary>
    internal void CloseSession(ulong session) => _ = _closeSession((nuint)session);

    /// <summary>
    /// Logs the user in. Returns <see langword="false"/> when the user was already logged in by
    /// another session of this process (so this caller must not log out).
    /// </summary>
    /// <param name="session">The session handle.</param>
    /// <param name="pinUtf8">The PIN as UTF-8, or <see langword="null"/> for a protected authentication path (PIN pad).</param>
    internal bool Login(ulong session, byte[]? pinUtf8)
    {
        using var memory = new NativeAllocations();
        nint pin = pinUtf8 is null ? 0 : memory.Copy(pinUtf8);
        nuint length = pinUtf8 is null ? 0 : (nuint)pinUtf8.Length;
        ulong rv = Layout.Normalize(_login((nuint)session, (nuint)CkConstants.CkuUser, pin, length));
        if (rv == CkConstants.CkrUserAlreadyLoggedIn)
        {
            return false;
        }

        Check("C_Login", rv);
        return true;
    }

    /// <summary>Logs out, ignoring errors (used on cleanup paths).</summary>
    internal void Logout(ulong session) => _ = _logout((nuint)session);

    /// <summary>Finds the objects matching an attribute template.</summary>
    internal IReadOnlyList<ulong> FindObjects(ulong session, IReadOnlyList<(ulong Type, byte[] Value)> template)
    {
        using var memory = new NativeAllocations();
        nint attributes = WriteTemplate(memory, template);
        Check("C_FindObjectsInit", Layout.Normalize(
            _findObjectsInit((nuint)session, attributes, (nuint)template.Count)));

        var result = new List<ulong>();
        try
        {
            const int batch = 32;
            nint handles = memory.Allocate(batch * Layout.ULongSize);
            nint count = memory.Allocate(Layout.ULongSize);
            while (true)
            {
                Check("C_FindObjects", Layout.Normalize(_findObjects((nuint)session, handles, batch, count)));
                int found = checked((int)Layout.ReadULong(count, 0));
                for (int i = 0; i < found; i++)
                {
                    result.Add(Layout.ReadULong(handles, i * Layout.ULongSize));
                }

                if (found < batch)
                {
                    break;
                }
            }
        }
        finally
        {
            _ = _findObjectsFinal((nuint)session);
        }

        return result;
    }

    /// <summary>Reads one attribute, or returns <see langword="null"/> when the object does not have it or it is sensitive.</summary>
    internal byte[]? GetAttribute(ulong session, ulong objectHandle, ulong type)
    {
        using var memory = new NativeAllocations();
        nint attribute = memory.Allocate(Layout.TypeValueLengthSize);
        Layout.WriteULong(attribute, 0, type);
        ulong rv = Layout.Normalize(_getAttributeValue((nuint)session, (nuint)objectHandle, attribute, 1));
        ulong length = Layout.ReadULong(attribute, Layout.TypeValueLengthLengthOffset);
        if (rv != CkConstants.CkrOk || length == Layout.UnavailableInformation)
        {
            return null;
        }

        int size = checked((int)length);
        nint value = memory.Allocate(size);
        Layout.WritePointer(attribute, Layout.TypeValueLengthPointerOffset, value);
        Check("C_GetAttributeValue", Layout.Normalize(
            _getAttributeValue((nuint)session, (nuint)objectHandle, attribute, 1)));
        return NativeAllocations.Read(value, checked((int)Layout.ReadULong(attribute, Layout.TypeValueLengthLengthOffset)));
    }

    /// <summary>Signs <paramref name="data"/> with a private key in one C_SignInit/C_Sign operation.</summary>
    internal byte[] Sign(ulong session, ulong key, ulong mechanismType, byte[]? mechanismParameter, byte[] data)
    {
        using var memory = new NativeAllocations();
        nint mechanism = memory.Allocate(Layout.TypeValueLengthSize);
        Layout.WriteULong(mechanism, 0, mechanismType);
        if (mechanismParameter is not null)
        {
            Layout.WritePointer(mechanism, Layout.TypeValueLengthPointerOffset, memory.Copy(mechanismParameter));
            Layout.WriteULong(mechanism, Layout.TypeValueLengthLengthOffset, (ulong)mechanismParameter.Length);
        }

        Check("C_SignInit", Layout.Normalize(_signInit((nuint)session, mechanism, (nuint)key)));

        nint input = memory.Copy(data);
        nint length = memory.Allocate(Layout.ULongSize);
        int capacity = 1024;
        nint signature = memory.Allocate(capacity);
        Layout.WriteULong(length, 0, (ulong)capacity);
        ulong rv = Layout.Normalize(_sign((nuint)session, input, (nuint)data.Length, signature, length));
        if (rv == CkConstants.CkrBufferTooSmall)
        {
            // The operation stays active and the driver reports the required size.
            capacity = checked((int)Layout.ReadULong(length, 0));
            signature = memory.Allocate(capacity);
            rv = Layout.Normalize(_sign((nuint)session, input, (nuint)data.Length, signature, length));
        }

        Check("C_Sign", rv);
        return NativeAllocations.Read(signature, checked((int)Layout.ReadULong(length, 0)));
    }

    /// <summary>Encodes a CK_ULONG attribute value (e.g. CKA_CLASS) for this layout.</summary>
    internal byte[] EncodeULong(ulong value)
    {
        byte[] encoded = new byte[Layout.ULongSize];
        for (int i = 0; i < encoded.Length; i++)
        {
            encoded[i] = (byte)(value >> (8 * i));
        }

        return BitConverter.IsLittleEndian ? encoded : [.. encoded.Reverse()];
    }

    /// <summary>Decodes a CK_ULONG attribute value.</summary>
    internal static ulong DecodeULong(byte[] value)
    {
        byte[] ordered = BitConverter.IsLittleEndian ? value : [.. value.Reverse()];
        ulong result = 0;
        for (int i = 0; i < Math.Min(ordered.Length, 8); i++)
        {
            result |= (ulong)ordered[i] << (8 * i);
        }

        return result;
    }

    /// <summary>Calls C_Initialize; a module another component initialized is used as it is and not finalized here.</summary>
    private void Initialize()
    {
        using var memory = new NativeAllocations();
        nint args = memory.Allocate(Layout.InitArgsSize);
        Layout.WriteULong(args, Layout.InitArgsFlagsOffset, CkConstants.CkfOsLockingOk);
        ulong rv = Layout.Normalize(_initialize(args));
        if (rv != CkConstants.CkrCryptokiAlreadyInitialized)
        {
            Check("C_Initialize", rv);
            _initializedByUs = true;
        }
    }

    private static string Key(string libraryPath) =>
        Path.IsPathRooted(libraryPath) ? Path.GetFullPath(libraryPath) : libraryPath;

    private static void Check(string function, ulong rv)
    {
        if (rv != CkConstants.CkrOk)
        {
            throw new Pkcs11Exception(function, rv);
        }
    }

    private static string PaddedText(byte[] text, int offset, int length) =>
        Encoding.UTF8.GetString(text, offset, length).TrimEnd(' ', '\0');

    private T Function<T>(nint functionList, int index)
        where T : Delegate
    {
        nint pointer = Layout.ReadPointer(functionList, Layout.FunctionOffset(index));
        if (pointer == 0)
        {
            throw new Pkcs11Exception($"The PKCS#11 library does not implement function #{index} of CK_FUNCTION_LIST.");
        }

        return Marshal.GetDelegateForFunctionPointer<T>(pointer);
    }

    private nint WriteTemplate(NativeAllocations memory, IReadOnlyList<(ulong Type, byte[] Value)> template)
    {
        nint attributes = memory.Allocate(template.Count * Layout.TypeValueLengthSize);
        for (int i = 0; i < template.Count; i++)
        {
            int offset = i * Layout.TypeValueLengthSize;
            Layout.WriteULong(attributes, offset, template[i].Type);
            Layout.WritePointer(attributes, offset + Layout.TypeValueLengthPointerOffset, memory.Copy(template[i].Value));
            Layout.WriteULong(attributes, offset + Layout.TypeValueLengthLengthOffset, (ulong)template[i].Value.Length);
        }

        return attributes;
    }
}
