# SimpleSign.Pdf

PDF structure parsing for .NET: cross-reference tables and streams, object
streams (ObjStm), page trees, AcroForm fields, signature dictionaries, and
byte ranges — all read-only, offline, and AOT-compatible.

## Quickstart

```csharp
using SimpleSign.Pdf;

await using var stream = File.OpenRead("signed.pdf");
IReadOnlyList<PdfSignatureField> fields =
    await PdfStructureReader.ReadSignatureFieldsAsync(stream);

foreach (PdfSignatureField field in fields)
{
    Console.WriteLine($"{field.FieldName}: {field.Reason}");
}
```

Usually consumed transitively via `SimpleSign.PAdES`; install directly to build
PDF tooling on top of the parser.

More at [github.com/eupassarin/SimpleSign](https://github.com/eupassarin/SimpleSign)
and the [docs](https://eupassarin.github.io/SimpleSign/docs/). MIT licensed.
