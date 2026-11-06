namespace SimpleSign.PAdES.Pdf;

internal readonly record struct PdfCrossRef(int ObjectNumber, long Offset, bool IsCompressed = false);
