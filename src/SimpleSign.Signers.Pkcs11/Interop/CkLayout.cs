using System.Runtime.InteropServices;

namespace SimpleSign.Signers.Pkcs11.Interop;

/// <summary>
/// Memory layout of the PKCS#11 structures on a platform. Cryptoki uses <c>unsigned long</c> for
/// CK_ULONG: 32 bits on Windows (where the headers also pack structures to 1 byte) and the pointer
/// size on Unix (natural alignment). Structures are read and written field by field so no
/// struct marshalling is involved.
/// </summary>
internal sealed class CkLayout
{
    private CkLayout(bool packed, int ulongSize, int pointerSize)
    {
        Packed = packed;
        ULongSize = ulongSize;
        PointerSize = pointerSize;
    }

    /// <summary>The layout of the running process.</summary>
    internal static CkLayout Current { get; } = Create(OperatingSystem.IsWindows(), IntPtr.Size);

    /// <summary>Whether structures are packed to 1 byte (Windows).</summary>
    internal bool Packed { get; }

    /// <summary>Size of CK_ULONG in bytes.</summary>
    internal int ULongSize { get; }

    /// <summary>Size of a pointer in bytes.</summary>
    internal int PointerSize { get; }

    /// <summary>Creates the layout for Windows (packed, 32-bit CK_ULONG) or Unix (natural, pointer-size CK_ULONG).</summary>
    internal static CkLayout Create(bool windows, int pointerSize) =>
        new(packed: windows, ulongSize: windows ? 4 : pointerSize, pointerSize);

    // CK_ATTRIBUTE and CK_MECHANISM share one shape: { CK_ULONG type; void* pValue; CK_ULONG len; }

    /// <summary>Offset of the pointer field in CK_ATTRIBUTE / CK_MECHANISM.</summary>
    internal int TypeValueLengthPointerOffset => Align(ULongSize, PointerSize);

    /// <summary>Offset of the length field in CK_ATTRIBUTE / CK_MECHANISM.</summary>
    internal int TypeValueLengthLengthOffset => Align(TypeValueLengthPointerOffset + PointerSize, ULongSize);

    /// <summary>Size of CK_ATTRIBUTE / CK_MECHANISM.</summary>
    internal int TypeValueLengthSize =>
        Align(TypeValueLengthLengthOffset + ULongSize, Math.Max(ULongSize, PointerSize));

    /// <summary>Size of CK_RSA_PKCS_PSS_PARAMS: { CK_ULONG hashAlg; CK_ULONG mgf; CK_ULONG sLen; }.</summary>
    internal int PssParamsSize => 3 * ULongSize;

    /// <summary>Offset of <c>flags</c> in CK_C_INITIALIZE_ARGS (after four mutex callbacks).</summary>
    internal int InitArgsFlagsOffset => 4 * PointerSize;

    /// <summary>Size of CK_C_INITIALIZE_ARGS.</summary>
    internal int InitArgsSize =>
        Align(Align(InitArgsFlagsOffset + ULongSize, PointerSize) + PointerSize, PointerSize);

    /// <summary>Offset of <c>flags</c> in CK_TOKEN_INFO (after label, manufacturer, model and serial).</summary>
    internal static int TokenInfoFlagsOffset => 96;

    /// <summary>A buffer comfortably larger than CK_TOKEN_INFO on every platform.</summary>
    internal static int TokenInfoBufferSize => 512;

    /// <summary>Offset of the first function pointer in CK_FUNCTION_LIST (after CK_VERSION).</summary>
    internal int FirstFunctionOffset => Align(2, PointerSize);

    /// <summary>Offset of the function at <paramref name="index"/> in CK_FUNCTION_LIST.</summary>
    internal int FunctionOffset(int index) => FirstFunctionOffset + (index * PointerSize);

    /// <summary>The CK_UNAVAILABLE_INFORMATION marker (all bits set in a CK_ULONG).</summary>
    internal ulong UnavailableInformation => ULongSize == 4 ? uint.MaxValue : ulong.MaxValue;

    /// <summary>Normalizes a CK_ULONG returned in a register (the upper half is undefined on Windows).</summary>
    internal ulong Normalize(nuint value) => ULongSize == 4 ? (uint)value : value;

    /// <summary>Writes a CK_ULONG.</summary>
    internal void WriteULong(nint pointer, int offset, ulong value)
    {
        if (ULongSize == 4)
        {
            Marshal.WriteInt32(pointer, offset, unchecked((int)(uint)value));
        }
        else
        {
            Marshal.WriteInt64(pointer, offset, unchecked((long)value));
        }
    }

    /// <summary>Reads a CK_ULONG.</summary>
    internal ulong ReadULong(nint pointer, int offset) =>
        ULongSize == 4
            ? unchecked((uint)Marshal.ReadInt32(pointer, offset))
            : unchecked((ulong)Marshal.ReadInt64(pointer, offset));

    /// <summary>Writes a pointer.</summary>
    internal void WritePointer(nint pointer, int offset, nint value)
    {
        if (PointerSize == 4)
        {
            Marshal.WriteInt32(pointer, offset, (int)value);
        }
        else
        {
            Marshal.WriteInt64(pointer, offset, value);
        }
    }

    /// <summary>Reads a pointer.</summary>
    internal nint ReadPointer(nint pointer, int offset) =>
        PointerSize == 4 ? Marshal.ReadInt32(pointer, offset) : (nint)Marshal.ReadInt64(pointer, offset);

    private int Align(int offset, int alignment) =>
        Packed ? offset : (offset + alignment - 1) / alignment * alignment;
}
