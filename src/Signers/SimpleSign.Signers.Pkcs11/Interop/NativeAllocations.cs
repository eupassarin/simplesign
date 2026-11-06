using System.Runtime.InteropServices;

namespace SimpleSign.Signers.Pkcs11.Interop;

/// <summary>
/// Tracks unmanaged buffers for one native call. Every buffer is zeroed before it is freed,
/// so PINs and signature inputs do not linger in freed memory.
/// </summary>
internal sealed class NativeAllocations : IDisposable
{
    private readonly List<(nint Pointer, int Length)> _buffers = [];

    /// <summary>Allocates a zero-filled buffer.</summary>
    internal nint Allocate(int length)
    {
        int size = Math.Max(length, 1);
        nint pointer = Marshal.AllocHGlobal(size);
        _buffers.Add((pointer, size));
        Zero(pointer, size);
        return pointer;
    }

    /// <summary>Allocates a buffer holding a copy of <paramref name="data"/>.</summary>
    internal nint Copy(ReadOnlySpan<byte> data)
    {
        nint pointer = Allocate(data.Length);
        if (!data.IsEmpty)
        {
            Marshal.Copy(data.ToArray(), 0, pointer, data.Length);
        }

        return pointer;
    }

    /// <summary>Reads <paramref name="length"/> bytes from an unmanaged buffer.</summary>
    internal static byte[] Read(nint pointer, int length)
    {
        byte[] data = new byte[length];
        if (length > 0)
        {
            Marshal.Copy(pointer, data, 0, length);
        }

        return data;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        foreach (var (pointer, length) in _buffers)
        {
            Zero(pointer, length);
            Marshal.FreeHGlobal(pointer);
        }

        _buffers.Clear();
    }

    private static void Zero(nint pointer, int length)
    {
        for (int i = 0; i < length; i++)
        {
            Marshal.WriteByte(pointer, i, 0);
        }
    }
}
