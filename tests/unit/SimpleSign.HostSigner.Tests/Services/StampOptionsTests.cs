using System.Text.Json;
using Shouldly;
using SimpleSign.HostSigner.Services;
using SimpleSign.PAdES.Signing;
using Xunit;

namespace SimpleSign.HostSigner.Tests.Services;

public class StampOptionsTests
{
    private static StampOptions? Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return StampOptions.FromJson(doc.RootElement);
    }

    [Fact]
    public void FromJson_NoStamp_ReturnsNull()
    {
        Parse("""{ "visibleStamp": true }""").ShouldBeNull();
        Parse("""{ "stamp": null }""").ShouldBeNull();
    }

    [Fact]
    public void FromJson_AllFields_AreRead()
    {
        var stamp = Parse("""
            { "stamp": {
                "page": 2, "x": 40, "y": 60.5, "width": 220, "height": 70,
                "signedByLabel": "Assinado digitalmente por", "reasonLabel": "Motivo: ",
                "locationLabel": "Local: ", "dateLabel": "Data: ",
                "dateFormat": "dd/MM/yyyy HH:mm", "timeZone": "-03:00",
                "showDate": false, "textAlign": "Center" } }
            """)!;

        stamp.Page.ShouldBe(2);
        stamp.X.ShouldBe(40f);
        stamp.Y.ShouldBe(60.5f);
        stamp.Width.ShouldBe(220f);
        stamp.Height.ShouldBe(70f);
        stamp.SignedByLabel.ShouldBe("Assinado digitalmente por");
        stamp.ReasonLabel.ShouldBe("Motivo: ");
        stamp.LocationLabel.ShouldBe("Local: ");
        stamp.DateLabel.ShouldBe("Data: ");
        stamp.DateFormat.ShouldBe("dd/MM/yyyy HH:mm");
        stamp.TimeZone!.BaseUtcOffset.ShouldBe(TimeSpan.FromHours(-3));
        stamp.ShowDate.ShouldBeFalse();
        stamp.TextAlignment.ShouldBe(SignatureTextAlignment.Center);
    }

    [Theory]
    [InlineData("""{ "stamp": { "timeZone": "Not/AZone" } }""", "timeZone")]
    [InlineData("""{ "stamp": { "textAlign": "justify" } }""", "textAlign")]
    [InlineData("""{ "stamp": { "width": -5 } }""", "width")]
    [InlineData("""{ "stamp": { "x": "abc" } }""", "x")]
    [InlineData("""{ "stamp": { "page": 0 } }""", "page")]
    [InlineData("""{ "stamp": "yes" }""", "stamp")]
    public void FromJson_InvalidField_ThrowsFormatException(string json, string field)
    {
        var ex = Should.Throw<FormatException>(() => Parse(json));
        ex.Message.ShouldContain(field);
    }

    [Fact]
    public void ToAppearance_WithoutPosition_AutoPositionsAndShowsGivenFields()
    {
        var appearance = new StampOptions { SignedByLabel = "Assinado por" }.ToAppearance(hasReason: true, hasLocation: false);

        appearance.AutoPosition.ShouldBeTrue();
        appearance.Page.ShouldBe(1);
        appearance.ShowReason.ShouldBeTrue();
        appearance.ShowLocation.ShouldBeFalse();
        appearance.SignedByLabel.ShouldBe("Assinado por");
        appearance.ReasonLabel.ShouldBe("Reason: ");
    }

    [Fact]
    public void ToAppearance_WithPosition_UsesCoordinates()
    {
        var appearance = new StampOptions { Page = 3, X = 100, Width = 180, TextAlignment = SignatureTextAlignment.Right }
            .ToAppearance(hasReason: false, hasLocation: true);

        appearance.AutoPosition.ShouldBeFalse();
        appearance.Page.ShouldBe(3);
        appearance.X.ShouldBe(100f);
        appearance.Y.ShouldBe(20f);
        appearance.Width.ShouldBe(180f);
        appearance.TextAlignment.ShouldBe(SignatureTextAlignment.Right);
        appearance.ShowLocation.ShouldBeTrue();
    }

    [Theory]
    [InlineData("UTC", 0)]
    [InlineData("+05:30", 330)]
    [InlineData("-0300", -180)]
    public void ParseTimeZone_Offsets_AreParsed(string value, int minutes) =>
        StampOptions.ParseTimeZone(value)!.BaseUtcOffset.ShouldBe(TimeSpan.FromMinutes(minutes));
}
