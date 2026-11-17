using Shouldly;
using SimpleSign.Cli.Commands;
using SimpleSign.Cli.Extensions;
using SimpleSign.Core.Http;

namespace SimpleSign.Cli.Tests;

[Collection(CliConsoleCollection.Name)]
[Trait("Category", "Unit")]
public sealed class TrustedValidationSettingsTests : IDisposable
{
    // The profile of a trust framework comes from an extension: the sample one of the tests.
    public TrustedValidationSettingsTests()
    {
        CliExtensions.Use([new SampleCliExtension()]);
    }

    public void Dispose() => CliExtensions.Use([]);

    [Fact]
    public async Task LoadTrustAsync_NoProfile_TrustsTheSystemRoots()
    {
        var settings = new ValidateCommand.Settings();

        await settings.LoadTrustAsync(DefaultHttpClientProvider.Instance, CancellationToken.None);

        settings.TrustsSystemRoots.ShouldBeTrue();
    }

    [Fact]
    public async Task LoadTrustAsync_NoSystemRoots_DoesNotTrustThem()
    {
        var settings = new ValidateCommand.Settings { NoSystemRoots = true };

        await settings.LoadTrustAsync(DefaultHttpClientProvider.Instance, CancellationToken.None);

        settings.TrustsSystemRoots.ShouldBeFalse();
    }

    [Fact]
    public async Task LoadTrustAsync_FrameworkProfile_DoesNotTrustTheSystemRoots()
    {
        var settings = new ValidateCommand.Settings { Profile = "sample" };

        await settings.LoadTrustAsync(DefaultHttpClientProvider.Instance, CancellationToken.None);

        settings.TrustsSystemRoots.ShouldBeFalse();
    }

    [Fact]
    public async Task LoadTrustAsync_TrustProfileOnly_KeepsTheSystemRoots()
    {
        // --trust-profile without --profile adds a framework's trust to SimpleSign's default, which trusts the system's roots.
        var settings = new ValidateCommand.Settings { TrustProfiles = ["sample"] };

        await settings.LoadTrustAsync(DefaultHttpClientProvider.Instance, CancellationToken.None);

        settings.TrustsSystemRoots.ShouldBeTrue();
    }
}
