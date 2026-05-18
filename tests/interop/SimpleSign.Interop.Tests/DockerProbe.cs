using System.Diagnostics;

namespace SimpleSign.Interop.Tests;

internal static class DockerProbe
{
    /// <summary>Returns true if <c>docker info</c> succeeds within 5 seconds.</summary>
    public static bool IsDockerAvailable()
    {
        return RunProbe("docker", "info");
    }

    /// <summary>Returns true if the named Docker image is locally available.</summary>
    public static bool ImageExists(string image)
    {
        return RunProbe("docker", $"image inspect {image}");
    }

    private static bool RunProbe(string command, string args, int timeoutMs = 10_000)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo(command, args)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            });
            if (p is null)
            {
                return false;
            }

            // Drain stdout/stderr asynchronously to prevent buffer deadlock
            p.StandardOutput.ReadToEnd();
            p.StandardError.ReadToEnd();
            return p.WaitForExit(timeoutMs) && p.ExitCode == 0;
        }
        catch (Exception)
        {
            return false;
        }
    }
}
