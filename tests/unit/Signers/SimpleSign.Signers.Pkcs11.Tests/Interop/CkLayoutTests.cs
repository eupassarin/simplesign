using System.Runtime.InteropServices;
using Shouldly;
using SimpleSign.Signers.Pkcs11.Interop;
using Xunit;

namespace SimpleSign.Signers.Pkcs11.Tests.Interop;

[Trait("Category", "Unit")]
public sealed class CkLayoutTests
{
    private static readonly CkLayout Windows = CkLayout.Create(windows: true, pointerSize: 8);
    private static readonly CkLayout Unix = CkLayout.Create(windows: false, pointerSize: 8);

    [Fact]
    public void Create_Windows_Uses32BitULongAndPacking()
    {
        Windows.ULongSize.ShouldBe(4);
        Windows.Packed.ShouldBeTrue();
    }

    [Fact]
    public void Create_Unix64_UsesPointerSizeULongAndNaturalAlignment()
    {
        Unix.ULongSize.ShouldBe(8);
        Unix.Packed.ShouldBeFalse();
    }

    [Fact]
    public void TypeValueLength_Windows_IsPackedTo16Bytes()
    {
        Windows.TypeValueLengthPointerOffset.ShouldBe(4);
        Windows.TypeValueLengthLengthOffset.ShouldBe(12);
        Windows.TypeValueLengthSize.ShouldBe(16);
    }

    [Fact]
    public void TypeValueLength_Unix64_IsAlignedTo24Bytes()
    {
        Unix.TypeValueLengthPointerOffset.ShouldBe(8);
        Unix.TypeValueLengthLengthOffset.ShouldBe(16);
        Unix.TypeValueLengthSize.ShouldBe(24);
    }

    [Fact]
    public void TypeValueLength_Unix32_IsAlignedTo12Bytes()
    {
        var unix32 = CkLayout.Create(windows: false, pointerSize: 4);
        unix32.TypeValueLengthPointerOffset.ShouldBe(4);
        unix32.TypeValueLengthLengthOffset.ShouldBe(8);
        unix32.TypeValueLengthSize.ShouldBe(12);
    }

    [Fact]
    public void FunctionOffset_Windows_StartsRightAfterVersion()
    {
        Windows.FunctionOffset(0).ShouldBe(2);
        Windows.FunctionOffset(43).ShouldBe(2 + (43 * 8));
    }

    [Fact]
    public void FunctionOffset_Unix64_StartsAtFirstAlignedPointer()
    {
        Unix.FunctionOffset(0).ShouldBe(8);
        Unix.FunctionOffset(43).ShouldBe(8 + (43 * 8));
    }

    [Fact]
    public void InitArgs_BothLayouts_PlaceFlagsAfterFourCallbacks()
    {
        Windows.InitArgsFlagsOffset.ShouldBe(32);
        Windows.InitArgsSize.ShouldBe(44);
        Unix.InitArgsFlagsOffset.ShouldBe(32);
        Unix.InitArgsSize.ShouldBe(48);
    }

    [Fact]
    public void PssParamsSize_BothLayouts_IsThreeULongs()
    {
        Windows.PssParamsSize.ShouldBe(12);
        Unix.PssParamsSize.ShouldBe(24);
    }

    [Fact]
    public void Normalize_Windows_DropsUndefinedUpperHalf() =>
        Windows.Normalize(unchecked((nuint)0xDEADBEEF_000000A0UL)).ShouldBe(0xA0UL);

    [Fact]
    public void Normalize_Unix_KeepsFullValue() =>
        Unix.Normalize(unchecked((nuint)0x1_0000_0000UL)).ShouldBe(0x1_0000_0000UL);

    [Fact]
    public void UnavailableInformation_MatchesULongWidth()
    {
        Windows.UnavailableInformation.ShouldBe(uint.MaxValue);
        Unix.UnavailableInformation.ShouldBe(ulong.MaxValue);
    }

    [Fact]
    public void WriteULong_Windows_WritesOnlyFourBytes()
    {
        nint buffer = Marshal.AllocHGlobal(16);
        try
        {
            Marshal.WriteInt64(buffer, 0, -1);
            Marshal.WriteInt64(buffer, 8, -1);
            Windows.WriteULong(buffer, 4, 0x11223344);

            Windows.ReadULong(buffer, 4).ShouldBe(0x11223344UL);
            Marshal.ReadInt32(buffer, 0).ShouldBe(-1);
            Marshal.ReadInt32(buffer, 8).ShouldBe(-1);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [Fact]
    public void WritePointer_RoundTrips()
    {
        nint buffer = Marshal.AllocHGlobal(16);
        try
        {
            Unix.WritePointer(buffer, 8, 0x1234_5678);
            Unix.ReadPointer(buffer, 8).ShouldBe(0x1234_5678);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }
}
