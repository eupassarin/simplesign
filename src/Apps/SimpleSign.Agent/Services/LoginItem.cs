using System.Globalization;
using System.Runtime.Versioning;
using System.Security;

namespace SimpleSign.Agent.Services;

/// <summary>
/// Starts the agent when the user logs in: a LaunchAgent on macOS, the per-user Run key on Windows
/// and an XDG autostart entry on Linux. The OS entry is the source of truth, not a setting.
/// </summary>
internal static class LoginItem
{
    private const string Id = "io.github.eupassarin.simplesign.agent";
    private const string WindowsValueName = "SimpleSign Agent";
    private const string WindowsRunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";

    /// <summary>Whether this platform supports starting at login.</summary>
    public static bool IsSupported => OperatingSystem.IsMacOS() || OperatingSystem.IsWindows() || OperatingSystem.IsLinux();

    /// <summary>Whether the agent is registered to start at login.</summary>
    public static bool IsEnabled
    {
        get
        {
            if (OperatingSystem.IsWindows())
            {
                return ReadWindows() is not null;
            }

            return EntryPath() is { } path && File.Exists(path);
        }
    }

    /// <summary>Registers or removes the login entry for <paramref name="executable"/>.</summary>
    public static void Set(bool enabled, string executable)
    {
        if (OperatingSystem.IsWindows())
        {
            WriteWindows(enabled ? $"\"{executable}\"" : null);
            return;
        }

        string? path = EntryPath();
        if (path is null)
        {
            return;
        }

        if (!enabled)
        {
            File.Delete(path);
            return;
        }

        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, OperatingSystem.IsMacOS() ? LaunchAgentPlist(executable) : AutostartEntry(executable));
    }

    /// <summary>The macOS LaunchAgent: runs once at login, not kept alive (Quit means quit).</summary>
    internal static string LaunchAgentPlist(string executable) => string.Create(CultureInfo.InvariantCulture, $"""
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
          <key>Label</key>
          <string>{Id}</string>
          <key>ProgramArguments</key>
          <array>
            <string>{SecurityElement.Escape(executable)}</string>
          </array>
          <key>RunAtLoad</key>
          <true/>
          <key>ProcessType</key>
          <string>Interactive</string>
        </dict>
        </plist>
        """);

    /// <summary>The freedesktop.org autostart entry.</summary>
    internal static string AutostartEntry(string executable) => $"""
        [Desktop Entry]
        Type=Application
        Name=SimpleSign Agent
        Comment=Local signing agent for web pages
        Exec="{executable.Replace("\"", "\\\"", StringComparison.Ordinal)}"
        X-GNOME-Autostart-enabled=true
        """;

    private static string? EntryPath()
    {
        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (OperatingSystem.IsMacOS())
        {
            return Path.Combine(home, "Library", "LaunchAgents", Id + ".plist");
        }

        if (OperatingSystem.IsLinux())
        {
            string config = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME") is { Length: > 0 } xdg ? xdg : Path.Combine(home, ".config");
            return Path.Combine(config, "autostart", Id + ".desktop");
        }

        return null;
    }

    [SupportedOSPlatform("windows")]
    private static string? ReadWindows()
    {
        using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(WindowsRunKey);
        return key?.GetValue(WindowsValueName) as string;
    }

    [SupportedOSPlatform("windows")]
    private static void WriteWindows(string? command)
    {
        using var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(WindowsRunKey);
        if (command is null)
        {
            key.DeleteValue(WindowsValueName, throwOnMissingValue: false);
        }
        else
        {
            key.SetValue(WindowsValueName, command);
        }
    }
}
