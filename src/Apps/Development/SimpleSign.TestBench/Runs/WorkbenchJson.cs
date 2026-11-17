using System.Text.Json;
using System.Text.Json.Serialization;

namespace SimpleSign.TestBench.Runs;

/// <summary>The JSON conventions of the API (camelCase, enums as names), for code that serializes outside a request.</summary>
internal static class WorkbenchJson
{
    public static JsonSerializerOptions Options { get; } = Create();

    private static JsonSerializerOptions Create()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        options.Converters.Add(new JsonStringEnumConverter());
        return options;
    }
}
