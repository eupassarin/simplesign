using System.Diagnostics;

namespace SimpleSign.Interop.Tests;

internal static class DockerProbe
{
    /// <summary>Returns true if <c>docker info</c> succeeds within 5 seconds.</summary>
    public static bool IsDockerAvailable()
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("docker", "info")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            });
            if (p is null)
            {
                return false;
            }
            return p.WaitForExit(5000) && p.ExitCode == 0;
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>Returns true if the named Docker image is locally available.</summary>
    public static bool ImageExists(string image)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("docker", $"image inspect {image}")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            });
            if (p is null)
            {
                return false;
            }
            return p.WaitForExit(5000) && p.ExitCode == 0;
        }
        catch (Exception)
        {
            return false;
        }
    }
}
