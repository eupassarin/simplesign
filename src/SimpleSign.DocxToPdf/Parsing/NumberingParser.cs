using System.Globalization;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Wordprocessing;
using SimpleSign.DocxToPdf.Model;

namespace SimpleSign.DocxToPdf.Parsing;

/// <summary>Parses numbering.xml into <see cref="NumberingDefinitions"/>.</summary>
internal sealed class NumberingParser
{
    private const float TwipsPerPoint = 20f;

    /// <summary>Parses the numbering definitions part.</summary>
    /// <param name="numberingPart">The numbering part (may be null).</param>
    /// <returns>Populated numbering definitions.</returns>
    public static NumberingDefinitions Parse(NumberingDefinitionsPart? numberingPart)
    {
        var defs = new NumberingDefinitions();

        if (numberingPart?.Numbering is null)
        {
            return defs;
        }

        // Parse abstract numbering definitions
        foreach (AbstractNum abstractNum in numberingPart.Numbering.Elements<AbstractNum>())
        {
            if (abstractNum.AbstractNumberId?.Value is null)
            {
                continue;
            }

            int abstractId = abstractNum.AbstractNumberId.Value;
            var levels = new List<DocNumberingLevel>();

            foreach (Level level in abstractNum.Elements<Level>())
            {
                var docLevel = new DocNumberingLevel
                {
                    Level = level.LevelIndex?.Value ?? 0,
                    Format = level.NumberingFormat?.Val?.Value.ToString() ?? "decimal",
                    TextTemplate = level.LevelText?.Val?.Value ?? "%1.",
                    StartValue = level.StartNumberingValue?.Val?.Value ?? 1
                };

                if (level.NumberingSymbolRunProperties?.RunFonts?.Ascii?.Value is not null)
                {
                    docLevel.FontName = level.NumberingSymbolRunProperties.RunFonts.Ascii.Value;
                }

                if (level.PreviousParagraphProperties?.Indentation?.Left?.Value is not null &&
                    int.TryParse(level.PreviousParagraphProperties.Indentation.Left.Value,
                        CultureInfo.InvariantCulture, out int indent))
                {
                    docLevel.IndentPt = indent / TwipsPerPoint;
                }

                levels.Add(docLevel);
            }

            defs.AbstractDefinitions[abstractId] = levels;
        }

        // Parse numbering instances
        foreach (NumberingInstance numInst in numberingPart.Numbering.Elements<NumberingInstance>())
        {
            if (numInst.NumberID?.Value is not null && numInst.AbstractNumId?.Val?.Value is not null)
            {
                defs.NumInstances[numInst.NumberID.Value] = numInst.AbstractNumId.Val.Value;
            }
        }

        return defs;
    }
}
