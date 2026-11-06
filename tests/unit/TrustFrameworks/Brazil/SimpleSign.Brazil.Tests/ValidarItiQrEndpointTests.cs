using System.Text.Json;
using Shouldly;
using SimpleSign.Brazil.ValidarIti;

namespace SimpleSign.Brazil.Tests;

/// <summary>The QR-code protocol of the VALIDAR developer guide (_format, _secretCode, JSON, 401/404).</summary>
[Trait("Category", "Unit")]
public sealed class ValidarItiQrEndpointTests
{
    private static readonly Uri Pdf = new("https://clinic.example/files/prescription-1.pdf");

    [Fact]
    public void IsValidarRequest_ValidarFormat_IsTrue()
    {
        ValidarItiQrEndpoint.IsValidarRequest("application/validador-iti+json").ShouldBeTrue();
        ValidarItiQrEndpoint.IsValidarRequest(null).ShouldBeFalse();
        ValidarItiQrEndpoint.IsValidarRequest("application/json").ShouldBeFalse();
    }

    [Fact]
    public void Respond_RightCode_Returns200WithSignedFiles()
    {
        var response = ValidarItiQrEndpoint.Respond("XIU8789Y", "XIU8789Y", [Pdf]);

        response.StatusCode.ShouldBe(200);
        using var json = JsonDocument.Parse(response.Json!);
        json.RootElement.GetProperty("version").GetString().ShouldBe("1.0.0");
        json.RootElement.GetProperty("prescription").GetProperty("signatureFiles")[0].GetProperty("url").GetString()
            .ShouldBe(Pdf.AbsoluteUri);
    }

    [Theory]
    [InlineData("WRONG")]
    [InlineData("")]
    [InlineData(null)]
    public void Respond_WrongOrMissingCode_Returns401(string? code)
    {
        var response = ValidarItiQrEndpoint.Respond(code, "XIU8789Y", [Pdf]);
        response.StatusCode.ShouldBe(401);
        response.Json.ShouldBeNull();
    }

    [Fact]
    public void Respond_EmptyExpectedCode_AcceptsEmptyCode() =>
        ValidarItiQrEndpoint.Respond(null, "", [Pdf]).StatusCode.ShouldBe(200);

    [Theory]
    [InlineData("has space")]
    [InlineData("ção")]
    public void Respond_NonAlphanumericExpectedCode_Throws(string code) =>
        Should.Throw<ArgumentException>(() => ValidarItiQrEndpoint.Respond(code, code, [Pdf]));

    [Fact]
    public void Respond_ExpectedCodeOver64Characters_Throws() =>
        Should.Throw<ArgumentException>(() => ValidarItiQrEndpoint.Respond("a", new string('a', 65), [Pdf]));

    [Fact]
    public void Respond_HttpFileUrl_Throws() =>
        Should.Throw<ArgumentException>(() => ValidarItiQrEndpoint.Respond("A", "A", [new Uri("http://clinic.example/a.pdf")]));

    [Fact]
    public void NotFound_Returns404() => ValidarItiQrEndpoint.NotFound().StatusCode.ShouldBe(404);

    [Fact]
    public void BuildQrCodeUrl_AddsTypeParameter()
    {
        ValidarItiQrEndpoint.BuildQrCodeUrl(new Uri("https://clinic.example/rx/1")).AbsoluteUri
            .ShouldBe("https://clinic.example/rx/1?type=prescricao");
        ValidarItiQrEndpoint.BuildQrCodeUrl(new Uri("https://clinic.example/rx?id=1"), "atestado").AbsoluteUri
            .ShouldBe("https://clinic.example/rx?id=1&type=atestado");
        ValidarItiQrEndpoint.BuildQrCodeUrl(new Uri("https://clinic.example/rx/1"), null).AbsoluteUri
            .ShouldBe("https://clinic.example/rx/1");
    }

    [Fact]
    public void BuildQrCodeUrl_HttpEndpoint_Throws() =>
        Should.Throw<ArgumentException>(() => ValidarItiQrEndpoint.BuildQrCodeUrl(new Uri("http://clinic.example/rx/1")));

    [Fact]
    public void BaseUrl_IsValidarPortal() => ValidarItiUrlBuilder.BaseUrl.ShouldBe("https://validar.iti.gov.br/");
}
