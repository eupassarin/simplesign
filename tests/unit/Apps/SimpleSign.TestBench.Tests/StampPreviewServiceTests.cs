using Shouldly;
using SimpleSign.TestBench.Signing;

namespace SimpleSign.TestBench.Tests;

/// <summary>The Stamp page's preview: the PDF signed with the stamp, the page and the rectangle the library wrote.</summary>
[Collection(TestBenchCollection.Name)]
[Trait("Category", "Unit")]
public sealed class StampPreviewServiceTests(TestBenchFixture fixture)
{
    private StampPreviewService Service() => new(fixture.Sandbox, fixture.Documents, fixture.Credentials);

    [SkippableFact]
    public async Task RenderAsync_FixedRectangle_ReturnsItAndThePage()
    {
        using var service = Service();
        var options = fixture.Options() with { Appearance = new AppearanceChoice { Visible = true, Page = 1, X = 100, Y = 120, Width = 200, Height = 60 } };

        var preview = await service.RenderAsync(options, default);

        preview.Page.ShouldBe(1);
        preview.Rect.ShouldNotBeNull().ShouldBe([100, 120, 200, 60]);
        fixture.Documents.TryGet(preview.FileId, out _).ShouldBeTrue();
    }

    [SkippableFact]
    public async Task RenderAsync_AutomaticPlacement_ReturnsWhereTheLibraryPutIt()
    {
        using var service = Service();
        var options = fixture.Options() with { Appearance = new AppearanceChoice { Visible = true, AutoPosition = true } };

        var preview = await service.RenderAsync(options, default);

        preview.Page.ShouldBe(1);
        var rect = preview.Rect.ShouldNotBeNull();
        rect[2].ShouldBeGreaterThan(0);
        rect[3].ShouldBeGreaterThan(0);
    }

    [SkippableFact]
    public async Task RenderAsync_Twice_KeepsOnlyTheLatestPreview()
    {
        using var service = Service();
        var options = fixture.Options() with { Appearance = new AppearanceChoice { Visible = true } };

        var first = await service.RenderAsync(options, default);
        var second = await service.RenderAsync(options with { Appearance = options.Appearance with { X = 200 } }, default);

        fixture.Documents.TryGet(first.FileId, out _).ShouldBeFalse();
        fixture.Documents.TryGet(second.FileId, out _).ShouldBeTrue();
        second.Rect![0].ShouldBe(200);
    }

    [Fact]
    public void Rect_PdfWithoutField_IsNull() =>
        StampPreviewService.Rect("%PDF-1.7\n%%EOF"u8.ToArray(), "Signature1").ShouldBeNull();
}
