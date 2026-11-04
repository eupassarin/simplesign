using Shouldly;
using SimpleSign.Signers.Pkcs11.Interop;
using Xunit;

namespace SimpleSign.Signers.Pkcs11.Tests;

[Trait("Category", "Unit")]
public sealed class Pkcs11ExceptionTests
{
    [Fact]
    public void Constructor_PinIncorrect_NamesFunctionAndReturnValue()
    {
        var ex = new Pkcs11Exception("C_Login", CkConstants.CkrPinIncorrect);

        ex.Function.ShouldBe("C_Login");
        ex.ReturnValue.ShouldBe(CkConstants.CkrPinIncorrect);
        ex.ReturnValueName.ShouldBe("CKR_PIN_INCORRECT");
        ex.IsPinIncorrect.ShouldBeTrue();
        ex.IsPinLocked.ShouldBeFalse();
        ex.Message.ShouldBe("C_Login failed with CKR_PIN_INCORRECT: The PIN is incorrect.");
    }

    [Fact]
    public void Constructor_PinLocked_SetsIsPinLocked() =>
        new Pkcs11Exception("C_Login", CkConstants.CkrPinLocked).IsPinLocked.ShouldBeTrue();

    [Fact]
    public void Constructor_UnknownReturnValue_UsesHexName() =>
        new Pkcs11Exception("C_Sign", 0x8000_0001).ReturnValueName.ShouldBe("CKR_0x80000001");

    [Fact]
    public void Constructor_MessageOnly_HasNoReturnValue()
    {
        var ex = new Pkcs11Exception("No token is connected.");

        ex.ReturnValue.ShouldBeNull();
        ex.ReturnValueName.ShouldBeNull();
        ex.Function.ShouldBeNull();
        ex.IsPinIncorrect.ShouldBeFalse();
    }

    [Fact]
    public void Constructor_IsSimpleSignException() =>
        new Pkcs11Exception("x").ShouldBeAssignableTo<SimpleSign.Core.SimpleSignException>();
}
