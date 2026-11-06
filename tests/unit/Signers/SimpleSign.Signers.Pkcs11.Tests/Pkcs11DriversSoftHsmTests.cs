using Shouldly;
using Xunit;

namespace SimpleSign.Signers.Pkcs11.Tests;

/// <summary>Driver discovery against a real module (SoftHSM2); skipped unless <c>SOFTHSM2_MODULE</c> is set.</summary>
[Trait("Category", "Pkcs11")]
[Collection(SoftHsmCollection.Name)]
public sealed class Pkcs11DriversSoftHsmTests(SoftHsmFixture hsm)
{
    [SkippableFact]
    public void FindTokens_SoftHsm_ListsItsToken()
    {
        Skip.If(hsm.SkipReason is not null, hsm.SkipReason);
        var installed = new[] { new Pkcs11InstalledDriver(Pkcs11Drivers.Known.Single(d => d.IsForTesting), hsm.ModulePath) };

        var found = Pkcs11Drivers.FindTokens(installed, Pkcs11Signer.ListTokens, CancellationToken.None);

        found.Single().Error.ShouldBeNull();
        found.Single().Tokens.ShouldContain(t => t.Label.Trim() == hsm.TokenLabel);
        Pkcs11Drivers.ChooseLibrary(found, hsm.TokenLabel).ShouldBe(hsm.ModulePath);
    }
}
