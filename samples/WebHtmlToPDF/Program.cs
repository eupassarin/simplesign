using SimpleSign.HtmlToPdf;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/", () => Results.Redirect("/samples/vaccination-record.html"));

app.MapPost("/convert", async (HttpRequest request) =>
{
    using var reader = new StreamReader(request.Body);
    var html = await reader.ReadToEndAsync();

    if (string.IsNullOrWhiteSpace(html))
    {
        return Results.BadRequest("HTML content is required.");
    }

    var pdfBytes = await HtmlToPdfConverter.Html(html).ConvertAsync();
    return Results.File(pdfBytes, "application/pdf", "output.pdf");
});

app.UseStaticFiles();
app.Run();
