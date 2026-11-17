using Shouldly;
using SimpleSign.Signers.Pkcs11.Interop;
using Xunit;

namespace SimpleSign.Signers.Pkcs11.Tests.Interop;

/// <summary>
/// The life of a loaded driver, against a real module (SoftHSM2); skipped unless
/// <c>SOFTHSM2_MODULE</c> is set.
/// </summary>
[Trait("Category", "Pkcs11")]
[Collection(SoftHsmCollection.Name)]
public sealed class Pkcs11ModuleSoftHsmTests(SoftHsmFixture hsm)
{
    [SkippableFact]
    public void Release_LastReference_KeepsTheDriverLoadedAndInitializesItAgain()
    {
        Skip.If(hsm.SkipReason is not null, hsm.SkipReason);
        var module = Pkcs11Module.Acquire(hsm.ModulePath);

        module.Release();

        Pkcs11Module.IsLoaded(hsm.ModulePath).ShouldBeTrue();
        var again = Pkcs11Module.Acquire(hsm.ModulePath);
        try
        {
            again.ShouldBeSameAs(module);
            again.GetSlotsWithToken().ShouldNotBeEmpty();
        }
        finally
        {
            again.Release();
        }
    }

    [SkippableFact]
    public void Release_ThreadsThatUsedTheDriverExit_ProcessKeepsRunning()
    {
        Skip.If(hsm.SkipReason is not null, hsm.SkipReason);
        var failures = new List<Exception>();

        // Each thread leaves its own state in the driver (and in the libcrypto it brings) and exits
        // after the last signer was disposed. When the driver was unloaded at that point, the cleanup
        // of that state ran in unmapped memory and killed the process on macOS (SIGSEGV in _pthread_exit).
        for (int round = 0; round < 20; round++)
        {
            var thread = new Thread(() =>
            {
                try
                {
                    Pkcs11Signer.Open(hsm.Options(SoftHsmFixture.RsaKeyLabel)).Dispose();
                }
                catch (Pkcs11Exception ex)
                {
                    lock (failures)
                    {
                        failures.Add(ex);
                    }
                }
            });
            thread.Start();
            thread.Join();
        }

        failures.ShouldBeEmpty();
        Pkcs11Module.IsLoaded(hsm.ModulePath).ShouldBeTrue();
    }
}
