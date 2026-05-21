namespace SimpleSign.DocxToPdf.Model;

/// <summary>Holds all numbering definitions from the document.</summary>
public sealed class NumberingDefinitions
{
    /// <summary>Gets the abstract numbering definitions keyed by abstractNumId.</summary>
    public Dictionary<int, List<DocNumberingLevel>> AbstractDefinitions { get; init; } = new();

    /// <summary>Gets the numbering instances mapping numId to abstractNumId.</summary>
    public Dictionary<int, int> NumInstances { get; init; } = new();

    /// <summary>Gets the levels for a given numbering instance ID.</summary>
    /// <param name="numId">The numbering instance ID.</param>
    /// <returns>The levels list or null if not found.</returns>
    public List<DocNumberingLevel>? GetLevels(int numId)
    {
        if (!NumInstances.TryGetValue(numId, out int abstractId))
        {
            return null;
        }

        return AbstractDefinitions.GetValueOrDefault(abstractId);
    }
}
