using Shouldly;
using SimpleSign.Core.Signing;
using Xunit;

namespace SimpleSign.Core.Tests.Signing;

[Trait("Category", "Unit")]
public sealed class TimestampOptionsTests
{
    [Fact]
    public void DigiCert_Preset_PointsToDigiCertTsa() =>
        TimestampOptions.DigiCert.Endpoint.ShouldBe(new Uri("http://timestamp.digicert.com"));

    [Fact]
    public void Sectigo_Preset_PointsToSectigoTsa() =>
        TimestampOptions.Sectigo.Endpoint.ShouldBe(new Uri("http://timestamp.sectigo.com"));

    [Fact]
    public void FreeTsa_Preset_PointsToFreeTsa() =>
        TimestampOptions.FreeTsa.Endpoint.ShouldBe(new Uri("https://freetsa.org/tsr"));

    [Fact]
    public void Presets_NoHttpClientProvider_UseBuilderProvider()
    {
        TimestampOptions.DigiCert.HttpClientProvider.ShouldBeNull();
        TimestampOptions.Sectigo.HttpClientProvider.ShouldBeNull();
        TimestampOptions.FreeTsa.HttpClientProvider.ShouldBeNull();
    }

    [Fact]
    public void Presets_UsedInProfile_ProduceTimestampedProfile() =>
        AdesBaselineProfile.Timestamped(TimestampOptions.DigiCert).ShouldNotBeNull();
}
