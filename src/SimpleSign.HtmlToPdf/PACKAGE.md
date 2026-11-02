# SimpleSign.HtmlToPdf

Dependency-free HTML → PDF conversion for .NET: a small layout engine with CSS
subset support (block/inline boxes, margins, paddings, tables, basic flex),
system-font metrics, and page breaks.

## Quickstart

```csharp
using SimpleSign.HtmlToPdf;

byte[] pdf = await HtmlToPdfConverter
    .Html("<h1>Hello, SimpleSign</h1><p>A paragraph of text.</p>")
    .ConvertAsync();
File.WriteAllBytes("output.pdf", pdf);
```

More at [github.com/eupassarin/SimpleSign](https://github.com/eupassarin/SimpleSign)
and the [docs](https://eupassarin.github.io/SimpleSign/). MIT licensed.
