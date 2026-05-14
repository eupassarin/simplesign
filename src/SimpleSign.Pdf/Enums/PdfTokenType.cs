namespace SimpleSign.Pdf.Enums;

internal enum PdfTokenType
{
    Unknown,
    Integer,
    Name,
    String,
    ArrayStart,
    ArrayEnd,
    DictStart,
    DictEnd,
    StreamStart,
    ObjectStart,
    ObjectEnd,
    Ref,
    Null,
    Boolean,
    Real,
    Eof
}
