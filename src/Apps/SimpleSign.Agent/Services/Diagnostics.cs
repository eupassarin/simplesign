using System.Globalization;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using SimpleSign.Agent.Localization;

namespace SimpleSign.Agent.Services;

/// <summary>What the About panel shows and "Copy diagnostics" copies.</summary>
internal static class Diagnostics
{
    /// <summary>The product version, without the source-control suffix.</summary>
    public static string Version { get; } =
        (Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? Assembly.GetExecutingAssembly().GetName().Version?.ToString(3)
            ?? "0.0.0").Split('+')[0];

    public static string OperatingSystemName => RuntimeInformation.OSDescription.Trim();

    public static string Architecture => RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant();

    /// <summary>".NET 10.0.1 · Native AOT" or ".NET 10.0.1".</summary>
    public static string Runtime =>
        RuntimeInformation.FrameworkDescription + (RuntimeFeature.IsDynamicCodeSupported ? "" : " · Native AOT");

    /// <summary>A plain-text report for a support request. It has no certificate data.</summary>
    public static string Report(AgentController controller, IReadOnlyList<string> drivers, int certificates)
    {
        var settings = controller.Settings;
        var text = new StringBuilder();
        text.AppendLine(CultureInfo.InvariantCulture, $"SimpleSign Agent {Version}");
        text.AppendLine(CultureInfo.InvariantCulture, $"OS: {OperatingSystemName} ({Architecture})");
        text.AppendLine(CultureInfo.InvariantCulture, $"Runtime: {Runtime}");
        text.AppendLine(CultureInfo.InvariantCulture, $"Language: {L.Language}");
        text.AppendLine(CultureInfo.InvariantCulture, $"State: {controller.State} ({controller.Address})");
        if (controller.Server.LastError is { } error)
        {
            text.AppendLine(CultureInfo.InvariantCulture, $"Last error: {error}");
        }

        text.AppendLine(CultureInfo.InvariantCulture, $"Start at login: {AgentController.StartsAtLogin}");
        text.AppendLine(CultureInfo.InvariantCulture, $"PIN cache (minutes): {settings.PinCacheMinutes}");
        text.AppendLine(CultureInfo.InvariantCulture, $"Sites: {settings.AllowedOrigins.Count} allowed, {settings.BlockedOrigins.Count} blocked");
        text.AppendLine(CultureInfo.InvariantCulture, $"Certificates found: {certificates}");
        text.AppendLine(CultureInfo.InvariantCulture, $"PKCS#11 drivers: {(drivers.Count == 0 ? "none" : string.Join("; ", drivers))}");
        return text.ToString();
    }
}
