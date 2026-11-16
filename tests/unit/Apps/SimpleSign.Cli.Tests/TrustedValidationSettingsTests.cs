using Shouldly;
using SimpleSign.Cli.Commands;
using SimpleSign.Core.Http;

namespace SimpleSign.Cli.Tests;

[Trait("Category", "Unit")]
public sealed class TrustedValidationSettingsTests
{
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
        var settings = new ValidateCommand.Settings { Profile = "icp-brasil" };

        await settings.LoadTrustAsync(DefaultHttpClientProvider.Instance, CancellationToken.None);

        settings.TrustsSystemRoots.ShouldBeFalse();
    }

    [Fact]
    public async Task LoadTrustAsync_TrustProfileOnly_KeepsTheSystemRoots()
    {
        // --trust-profile without --profile adds a framework's trust to SimpleSign's default, which trusts the system's roots.
        var settings = new ValidateCommand.Settings { TrustProfiles = ["icp-brasil"] };

        await settings.LoadTrustAsync(DefaultHttpClientProvider.Instance, CancellationToken.None);

        settings.TrustsSystemRoots.ShouldBeTrue();
    }
}
