using Shouldly;
using Xunit;

namespace SimpleSign.Signers.Pkcs11.Tests;

/// <summary>Argument and driver-loading checks that need no token. Token tests are in <see cref="Pkcs11SignerSoftHsmTests"/>.</summary>
[Trait("Category", "Unit")]
public sealed class Pkcs11SignerTests
{
    private static string NonPkcs11Library =>
        OperatingSystem.IsWindows() ? "kernel32.dll"
        : OperatingSystem.IsMacOS() ? "/usr/lib/libSystem.B.dylib"
        : "libc.so.6";

    [Fact]
    public void Open_NullOptions_ThrowsArgumentNullException() =>
        Should.Throw<ArgumentNullException>(() => Pkcs11Signer.Open(null!));

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    public void Open_BlankLibraryPath_ThrowsArgumentException(string path) =>
        Should.Throw<ArgumentException>(() => Pkcs11Signer.Open(new Pkcs11SignerOptions { LibraryPath = path }));

    [Fact]
    public void Open_MissingLibrary_ThrowsPkcs11Exception()
    {
        var ex = Should.Throw<Pkcs11Exception>(() =>
            Pkcs11Signer.Open(new Pkcs11SignerOptions { LibraryPath = "/nonexistent/libpkcs11-missing.so" }));

        ex.Message.ShouldContain("could not be loaded");
        ex.ReturnValue.ShouldBeNull();
    }

    [Fact]
    public void Open_LibraryWithoutGetFunctionList_ThrowsPkcs11Exception()
    {
        var ex = Should.Throw<Pkcs11Exception>(() =>
            Pkcs11Signer.Open(new Pkcs11SignerOptions { LibraryPath = NonPkcs11Library }));

        ex.Message.ShouldContain("not a PKCS#11 library");
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public void ListTokens_BlankLibraryPath_ThrowsArgumentException(string path) =>
        Should.Throw<ArgumentException>(() => Pkcs11Signer.ListTokens(path));

    [Fact]
    public void ListTokens_MissingLibrary_ThrowsPkcs11Exception() =>
        Should.Throw<Pkcs11Exception>(() => Pkcs11Signer.ListTokens("/nonexistent/libpkcs11-missing.so"));
}
