using System.Runtime.InteropServices;

namespace SimpleSign.Signers.Pkcs11;

/// <summary>A token or smartcard PKCS#11 driver and where its vendor installs it on each OS.</summary>
/// <param name="Vendor">The vendor (e.g. "SafeNet / Thales").</param>
/// <param name="Product">The product or middleware (e.g. "eToken / SafeNet Authentication Client").</param>
/// <param name="WindowsPaths">Library paths on Windows; <c>%VARIABLE%</c> is expanded.</param>
/// <param name="LinuxPaths">Library paths on Linux.</param>
/// <param name="MacPaths">Library paths on macOS.</param>
/// <param name="IsForTesting">A software token for development (SoftHSM), not a real device.</param>
public sealed record Pkcs11Driver(
    string Vendor,
    string Product,
    IReadOnlyList<string> WindowsPaths,
    IReadOnlyList<string> LinuxPaths,
    IReadOnlyList<string> MacPaths,
    bool IsForTesting = false)
{
    /// <summary>The paths for the OS this process runs on.</summary>
    public IReadOnlyList<string> PathsForCurrentPlatform => PathsFor(Pkcs11Drivers.CurrentPlatform());

    internal IReadOnlyList<string> PathsFor(OSPlatform platform) =>
        platform == OSPlatform.Windows ? WindowsPaths : platform == OSPlatform.OSX ? MacPaths : LinuxPaths;
}

/// <summary>A driver found on this machine.</summary>
/// <param name="Driver">The catalog entry (or a custom one for <see cref="Pkcs11Drivers.LibraryEnvironmentVariable"/>).</param>
/// <param name="LibraryPath">The library file that exists.</param>
public sealed record Pkcs11InstalledDriver(Pkcs11Driver Driver, string LibraryPath);

/// <summary>The tokens one installed driver reports, or why it could not be loaded.</summary>
/// <param name="Driver">The driver.</param>
/// <param name="Tokens">The connected tokens (the caller owns their certificates).</param>
/// <param name="Error">Why the driver could not be loaded or queried; null when it worked.</param>
public sealed record Pkcs11DriverTokens(Pkcs11InstalledDriver Driver, IReadOnlyList<Pkcs11TokenInfo> Tokens, string? Error);

/// <summary>
/// Finds the PKCS#11 drivers of the A3 tokens and smartcards used in Brazil (and generic OpenSC
/// readers) where their vendors install them, so users do not need to know the library path.
/// </summary>
/// <example>
/// <code>
/// foreach (var found in await Pkcs11Drivers.FindTokensAsync())
/// {
///     foreach (var token in found.Tokens)
///     {
///         Console.WriteLine($"{found.Driver.Driver.Product}: {token.Label} ({found.Driver.LibraryPath})");
///     }
/// }
/// </code>
/// </example>
public static class Pkcs11Drivers
{
    /// <summary>
    /// Environment variable with extra driver paths, separated by <see cref="Path.PathSeparator"/>;
    /// they are listed before the catalog.
    /// </summary>
    public const string LibraryEnvironmentVariable = "SIMPLESIGN_PKCS11_LIBRARY";

    private const string Sys = "%SystemRoot%\\System32\\";

    /// <summary>The known drivers and their default install locations.</summary>
    public static IReadOnlyList<Pkcs11Driver> Known { get; } =
    [
        new("SafeNet / Thales", "eToken / SafeNet Authentication Client",
            [Sys + "eTPKCS11.dll"],
            ["/usr/lib/libeTPkcs11.so", "/usr/lib64/libeTPkcs11.so", "/usr/lib/libeToken.so", "/usr/lib64/libeToken.so"],
            ["/usr/local/lib/libeTPkcs11.dylib", "/Library/Frameworks/eToken.framework/Versions/A/libeToken.dylib"]),
        new("A.E.T. / G+D", "SafeSign Identity Client (StarSign, Perto)",
            [Sys + "aetpkss1.dll"],
            ["/usr/lib/libaetpkss.so", "/usr/lib/libaetpkss.so.3", "/usr/local/lib/libaetpkss.so"],
            ["/usr/local/lib/libaetpkss.dylib", "/usr/local/lib/libaetpkss.3.dylib"]),
        new("Watchdata", "ProxKey / Watchdata ICP-Brasil",
            [Sys + "WDPKCS.dll", Sys + "Watchdata\\Watchdata Brazil CSP v1.0\\WDPKCS.dll", Sys + "WDICP_P11_CCID_v34.dll"],
            ["/usr/lib/watchdata/ICP/lib/libwdpkcs_icp.so", "/usr/lib/watchdata/lib/libwdpkcs.so", "/opt/watchdata/lib64/libwdpkcs.so",
             "/usr/lib/libwdpkcs.so", "/usr/local/lib/libwdpkcs.so", "/usr/local/lib64/libwdpkcs.so"],
            ["/usr/local/lib/libwdpkcs.dylib", "/usr/lib/libwdpkcs.dylib"]),
        new("Gemalto / Thales", "IDPrime / IDGo 800",
            ["%ProgramFiles%\\Gemalto\\IDGo 800 PKCS11\\IDPrimePKCS1164.dll", "%ProgramFiles(x86)%\\Gemalto\\IDGo 800 PKCS11\\IDPrimePKCS11.dll"],
            ["/usr/lib/libIDPrimePKCS11.so", "/usr/lib64/libIDPrimePKCS11.so"],
            ["/usr/local/lib/libIDPrimePKCS11.dylib"]),
        new("Gemalto / Gemplus", "GemSafe",
            [Sys + "gclib.dll", Sys + "pk2priv.dll", "%ProgramFiles%\\Gemplus\\GemSafe Libraries\\BIN\\gclib.dll"],
            ["/usr/lib/libgclib.so"],
            []),
        new("Oberthur / IDEMIA", "AWP (Certisign, Cosmo)",
            [Sys + "OcsCryptoki.dll", "%ProgramFiles(x86)%\\Oberthur Technologies\\AWP\\DLLs\\OcsCryptolib_P11.dll"],
            ["/usr/local/AWP/lib/libOcsCryptoki.so"],
            ["/usr/local/AWP/lib/libOcsCryptoki.dylib"]),
        new("Pronova", "ePass / NG",
            [Sys + "ngp11v211.dll", Sys + "asepkcs.dll", Sys + "acospkcs11.dll"],
            ["/usr/lib/libepsng_p11.so", "/usr/local/ngsrv/libepsng_p11.so.1", "/usr/lib/libasepkcs.so"],
            ["/usr/local/lib/libepsng_p11.dylib"]),
        new("Feitian", "ePass2003",
            [Sys + "eps2003csp11v2.dll", Sys + "eps2003csp11.dll"],
            ["/usr/lib/ePass2003-Linux-x64/x86_64/redist/libcastle.so.1.0.0", "/usr/local/lib/libcastle.so.1.0.0"],
            ["/usr/local/lib/libcastle.1.0.0.dylib"]),
        new("Safeweb", "Safeweb token (cmP11)",
            [Sys + "cmP11.dll"],
            ["/usr/lib/libcmP11.so"],
            []),
        new("SERPRO", "NeoID",
            [Sys + "SerproPkcs11.dll"],
            ["/usr/lib/libneoidp11.so"],
            []),
        new("Dexon", "DXSafe",
            [Sys + "DXSafePKCS11.dll"],
            ["/etc/Dexon/DXSafe/libDXSafePKCS11.X64.so"],
            []),
        new("Soluti", "birdID (cloud certificate, Assistente Desktop)",
            ["%ProgramFiles%\\Assistente Desktop birdID\\resources\\extraResources\\windows\\x64\\vault-pkcs11.dll"],
            ["/opt/Assistente Desktop birdID/resources/extraResources/linux/x64/vault-pkcs11.so"],
            ["/Applications/Assistente Desktop birdID.app/Contents/Resources/extraResources/mac/vault-pkcs11.dylib"]),
        new("Certisign", "desktopID (cloud certificate)",
            [Sys + "desktopID_Provider.dll"],
            [],
            []),
        new("OpenSC", "OpenSC (generic smartcard readers)",
            ["%ProgramFiles%\\OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll"],
            ["/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so", "/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so",
             "/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so", "/usr/lib64/opensc-pkcs11.so", "/usr/lib64/pkcs11/opensc-pkcs11.so",
             "/usr/lib/opensc-pkcs11.so", "/usr/lib/pkcs11/opensc-pkcs11.so"],
            ["/Library/OpenSC/lib/opensc-pkcs11.so", "/opt/homebrew/lib/opensc-pkcs11.so", "/usr/local/lib/opensc-pkcs11.so"]),
        new("OpenDNSSEC", "SoftHSM 2 (software token for development)",
            ["%ProgramFiles%\\SoftHSM2\\lib\\softhsm2-x64.dll"],
            ["/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so", "/usr/local/lib/softhsm/libsofthsm2.so"],
            ["/opt/homebrew/lib/softhsm/libsofthsm2.so", "/usr/local/lib/softhsm/libsofthsm2.so"],
            IsForTesting: true),
    ];

    /// <summary>
    /// The drivers installed on this machine: the libraries of <see cref="LibraryEnvironmentVariable"/>
    /// first, then the catalog entries whose files exist. Nothing is loaded.
    /// </summary>
    public static IReadOnlyList<Pkcs11InstalledDriver> DetectInstalled() =>
        DetectInstalled(CurrentPlatform(), File.Exists, Environment.GetEnvironmentVariable);

    internal static IReadOnlyList<Pkcs11InstalledDriver> DetectInstalled(
        OSPlatform platform, Func<string, bool> exists, Func<string, string?> environment)
    {
        var comparer = platform == OSPlatform.Windows ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        var seen = new HashSet<string>(comparer);
        var found = new List<Pkcs11InstalledDriver>();
        char separator = platform == OSPlatform.Windows ? ';' : ':';
        var custom = new Pkcs11Driver("Custom", LibraryEnvironmentVariable, [], [], []);
        foreach (string path in (environment(LibraryEnvironmentVariable) ?? "").Split(separator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (exists(path) && seen.Add(path))
            {
                found.Add(new Pkcs11InstalledDriver(custom, path));
            }
        }

        foreach (var driver in Known)
        {
            foreach (string template in driver.PathsFor(platform))
            {
                string path = platform == OSPlatform.Windows ? Expand(template, environment) : template;
                if (path.Length > 0 && exists(path) && seen.Add(path))
                {
                    found.Add(new Pkcs11InstalledDriver(driver, path));
                }
            }
        }

        return found.AsReadOnly();
    }

    /// <summary>
    /// Loads each installed driver and lists its connected tokens (no PIN needed). A driver that
    /// cannot be loaded is reported with its error; a token seen through two drivers is listed once.
    /// The caller owns the returned certificates.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token (checked between drivers).</param>
    public static Task<IReadOnlyList<Pkcs11DriverTokens>> FindTokensAsync(CancellationToken cancellationToken = default) =>
        Task.Run(() => FindTokens(DetectInstalled(), Pkcs11Signer.ListTokens, cancellationToken), cancellationToken);

    /// <summary>
    /// The library of the installed driver that sees the token: the one labelled
    /// <paramref name="tokenLabel"/>, or the only connected token when no label is given.
    /// </summary>
    /// <param name="tokenLabel">The token label; null when a single token is connected.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The library path, for <see cref="Pkcs11SignerOptions.LibraryPath"/>.</returns>
    /// <exception cref="Pkcs11Exception">No installed driver sees the token, or several tokens are connected and no label was given.</exception>
    public static async Task<string> FindLibraryAsync(string? tokenLabel = null, CancellationToken cancellationToken = default) =>
        ChooseLibrary(await FindTokensAsync(cancellationToken).ConfigureAwait(false), tokenLabel);

    internal static string ChooseLibrary(IReadOnlyList<Pkcs11DriverTokens> found, string? tokenLabel)
    {
        try
        {
            var matches = found
                .SelectMany(f => f.Tokens.Select(t => (f.Driver.LibraryPath, Token: t)))
                .Where(m => tokenLabel is null || string.Equals(m.Token.Label.Trim(), tokenLabel.Trim(), StringComparison.Ordinal))
                .ToList();
            return matches switch
            {
                [var single] => single.LibraryPath,
                [] => throw new Pkcs11Exception(tokenLabel is null
                    ? "No connected token was found through the installed PKCS#11 drivers. Pass the driver path explicitly."
                    : $"No installed PKCS#11 driver sees a token labelled '{tokenLabel}'."),
                _ => throw new Pkcs11Exception(
                    $"Several tokens are connected ({string.Join(", ", matches.Select(m => m.Token.Label.Trim()))}); choose one by its label."),
            };
        }
        finally
        {
            foreach (var certificate in found.SelectMany(f => f.Tokens).SelectMany(t => t.Certificates))
            {
                certificate.Certificate.Dispose();
            }
        }
    }

    internal static IReadOnlyList<Pkcs11DriverTokens> FindTokens(
        IReadOnlyList<Pkcs11InstalledDriver> drivers, Func<string, IReadOnlyList<Pkcs11TokenInfo>> listTokens, CancellationToken cancellationToken)
    {
        var serials = new HashSet<string>(StringComparer.Ordinal);
        var result = new List<Pkcs11DriverTokens>();
        foreach (var driver in drivers)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var tokens = listTokens(driver.LibraryPath)
                    .Where(t => string.IsNullOrEmpty(t.SerialNumber) || serials.Add(t.SerialNumber))
                    .ToList();
                result.Add(new Pkcs11DriverTokens(driver, tokens.AsReadOnly(), null));
            }
            catch (Pkcs11Exception ex)
            {
                result.Add(new Pkcs11DriverTokens(driver, [], ex.Message));
            }
        }

        return result.AsReadOnly();
    }

    internal static OSPlatform CurrentPlatform() =>
        OperatingSystem.IsWindows() ? OSPlatform.Windows : OperatingSystem.IsMacOS() ? OSPlatform.OSX : OSPlatform.Linux;

    /// <summary>Expands <c>%NAME%</c>; a path whose variable is not set expands to an empty string (skipped).</summary>
    internal static string Expand(string template, Func<string, string?> environment)
    {
        var result = new System.Text.StringBuilder();
        int index = 0;
        while (index < template.Length)
        {
            int start = template.IndexOf('%', index);
            int end = start < 0 ? -1 : template.IndexOf('%', start + 1);
            if (end < 0)
            {
                result.Append(template, index, template.Length - index);
                break;
            }

            result.Append(template, index, start - index);
            string? value = environment(template[(start + 1)..end]);
            if (string.IsNullOrEmpty(value))
            {
                return "";
            }

            result.Append(value);
            index = end + 1;
        }

        return result.ToString();
    }
}
