using System.Runtime.InteropServices;
using Shouldly;
using Xunit;

namespace SimpleSign.Signers.Pkcs11.Tests;

[Trait("Category", "Unit")]
public sealed class Pkcs11DriversTests
{
    [Fact]
    public void Known_EveryPathIsAbsoluteAndUnique()
    {
        foreach (var platform in new[] { OSPlatform.Windows, OSPlatform.Linux, OSPlatform.OSX })
        {
            var paths = Pkcs11Drivers.Known.SelectMany(d => d.PathsFor(platform)).ToList();
            paths.ShouldBeUnique();
            if (platform == OSPlatform.Windows)
            {
                paths.ShouldAllBe(p => p.StartsWith('%'));
            }
            else
            {
                paths.ShouldAllBe(p => p.StartsWith('/'));
            }
        }
    }

    [Fact]
    public void Known_CoversTheCommonBrazilianTokens()
    {
        var vendors = Pkcs11Drivers.Known.Select(d => d.Vendor).ToList();
        vendors.ShouldContain("SafeNet / Thales");
        vendors.ShouldContain("Watchdata");
        vendors.ShouldContain("A.E.T. / G+D");
        vendors.ShouldContain("OpenSC");
        Pkcs11Drivers.Known.Count(d => d.IsForTesting).ShouldBe(1);
    }

    [Fact]
    public void DetectInstalled_Linux_FindsExistingFilesOnly()
    {
        var files = new HashSet<string> { "/usr/lib/libeTPkcs11.so", "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so" };

        var found = Pkcs11Drivers.DetectInstalled(OSPlatform.Linux, files.Contains, _ => null);

        found.Select(f => f.LibraryPath).ShouldBe(["/usr/lib/libeTPkcs11.so", "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"]);
        found[0].Driver.Vendor.ShouldBe("SafeNet / Thales");
    }

    [Fact]
    public void DetectInstalled_Windows_ExpandsVariables()
    {
        var env = new Dictionary<string, string> { ["SystemRoot"] = @"C:\Windows", ["ProgramFiles"] = @"C:\Program Files" };
        var files = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { @"C:\Windows\System32\aetpkss1.dll", @"c:\program files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll" };

        var found = Pkcs11Drivers.DetectInstalled(OSPlatform.Windows, files.Contains, n => env.GetValueOrDefault(n));

        found.Select(f => f.Driver.Vendor).ShouldBe(["A.E.T. / G+D", "OpenSC"]);
        found[0].LibraryPath.ShouldBe(@"C:\Windows\System32\aetpkss1.dll");
    }

    [Fact]
    public void DetectInstalled_EnvironmentVariable_ListedFirstAndNotDuplicated()
    {
        var files = new HashSet<string> { "/opt/custom/libtoken.so", "/usr/lib/libeTPkcs11.so" };
        string? Env(string name) => name == Pkcs11Drivers.LibraryEnvironmentVariable ? "/opt/custom/libtoken.so:/missing.so:/usr/lib/libeTPkcs11.so" : null;

        var found = Pkcs11Drivers.DetectInstalled(OSPlatform.Linux, files.Contains, Env);

        found.Select(f => f.LibraryPath).ShouldBe(["/opt/custom/libtoken.so", "/usr/lib/libeTPkcs11.so"]);
        found.ShouldAllBe(f => f.Driver.Vendor == "Custom");
    }

    [Theory]
    [InlineData(@"%SystemRoot%\System32\x.dll", @"C:\Windows\System32\x.dll")]
    [InlineData(@"%ProgramFiles(x86)%\Vendor\x.dll", "")]
    [InlineData("no variables", "no variables")]
    public void Expand_ReplacesKnownVariablesAndDropsPathsWithUnsetOnes(string template, string expected) =>
        Pkcs11Drivers.Expand(template, n => n == "SystemRoot" ? @"C:\Windows" : null).ShouldBe(expected);

    [Fact]
    public void FindTokens_DriverThatFails_ReportedWithError()
    {
        var drivers = new[] { Installed("/a.so"), Installed("/b.so") };

        var found = Pkcs11Drivers.FindTokens(drivers, path => path == "/a.so" ? throw new Pkcs11Exception("cannot load") : [Token("T1", "S1")], CancellationToken.None);

        found[0].Error.ShouldBe("cannot load");
        found[1].Tokens.Single().Label.ShouldBe("T1");
    }

    [Fact]
    public void FindTokens_SameTokenThroughTwoDrivers_ListedOnce()
    {
        var drivers = new[] { Installed("/a.so"), Installed("/b.so") };

        var found = Pkcs11Drivers.FindTokens(drivers, _ => [Token("T1", "S1")], CancellationToken.None);

        found.SelectMany(f => f.Tokens).Count().ShouldBe(1);
    }

    [Fact]
    public void ChooseLibrary_SingleToken_ItsLibrary() =>
        Pkcs11Drivers.ChooseLibrary([new(Installed("/a.so"), [Token("T1", "S1")], null)], null).ShouldBe("/a.so");

    [Fact]
    public void ChooseLibrary_ByLabel_PicksTheMatchingDriver() =>
        Pkcs11Drivers.ChooseLibrary(
            [new(Installed("/a.so"), [Token("T1", "S1")], null), new(Installed("/b.so"), [Token("T2", "S2")], null)], "T2")
            .ShouldBe("/b.so");

    [Fact]
    public void ChooseLibrary_SeveralTokensWithoutLabel_Throws() =>
        Should.Throw<Pkcs11Exception>(() => Pkcs11Drivers.ChooseLibrary(
            [new(Installed("/a.so"), [Token("T1", "S1"), Token("T2", "S2")], null)], null))
            .Message.ShouldContain("T1");

    [Fact]
    public void ChooseLibrary_NoToken_Throws() =>
        Should.Throw<Pkcs11Exception>(() => Pkcs11Drivers.ChooseLibrary([], null));

    private static Pkcs11InstalledDriver Installed(string path) => new(Pkcs11Drivers.Known[0], path);

    private static Pkcs11TokenInfo Token(string label, string serial) =>
        new(0, label, "Vendor", "Model", serial, IsLoginRequired: true, HasProtectedAuthenticationPath: false, IsPinLocked: false, []);
}
