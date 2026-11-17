using System.IO.Compression;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Shouldly;
using SimpleSign.Brazil.GovBr;
using SimpleSign.Brazil.IcpBrasil;
using SimpleSign.CAdES;
using SimpleSign.Cli.Commands;
using SimpleSign.Cli.Extensibility;
using SimpleSign.Cli.Extensions;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Policies;
using SimpleSign.PAdES.DependencyInjection;
using SimpleSign.XAdES;
using SimpleSign.XAdES.TrustedLists;
using Spectre.Console;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Tests;

/// <summary>An extension for the tests: one profile, one policy of each kind, one trusted-list profile and one command.</summary>
public sealed class SampleCliExtension : ICliExtension
{
    public string Name => "sample";

    public string Title => "Sample framework";

    public CliExtensionContext? Context { get; private set; }

    public void Initialize(CliExtensionContext context) => Context = context;

    public void AddCommands(IConfigurator config) =>
        config.AddBranch("sample", branch => branch.AddCommand<SampleCommand>("hello").WithDescription("Says hello"));

    public IReadOnlyList<CliProfile> Profiles { get; } =
    [
        new()
        {
            Name = "sample", Title = "Sample framework", SigningPolicy = "sample", ValidationPolicy = "sample", Trust = "nobody",
            LoadAsync = (_, _) => Task.FromResult(new TrustProfile("sample", "Sample framework", SigningPolicy.Default, ValidationPolicy.Default, [], [])),
        },
        // A name the CLI already has: it must not replace the CLI's own.
        new() { Name = "sandbox", Title = "Not the Sandbox", LoadAsync = (_, _) => throw new InvalidOperationException("replaced") },
    ];

    public IReadOnlyDictionary<string, Func<SigningPolicy>> SigningPolicies { get; } = new Dictionary<string, Func<SigningPolicy>>
    {
        ["sample"] = () => SigningPolicy.Default.WithName("Sample signing policy"),
        ["default"] = () => SigningPolicy.Default.WithName("Not the default"),
    };

    public IReadOnlyDictionary<string, Func<ValidationPolicy>> ValidationPolicies { get; } = new Dictionary<string, Func<ValidationPolicy>>
    {
        ["sample"] = () => ValidationPolicy.Default.WithName("Sample validation policy"),
    };

    public IReadOnlyList<CliTrustedListProfile> TrustedListProfiles { get; } =
    [
        new() { Name = "sample", Options = _ => new TrustedListOptions(), HasBundledSigner = true, UnverifiableListGivesNoAnchors = true },
    ];

    // Spectre.Console.Cli creates the command and its settings by reflection.
#pragma warning disable CA1812
    private sealed class SampleCommand : Command<SampleCommand.Settings>
    {
        internal sealed class Settings : CommandSettings
        {
        }
#pragma warning restore CA1812

        public override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            AnsiConsole.MarkupLine("hello from the sample extension");
            return 0;
        }
    }
}

/// <summary>The extensions of the CLI: how they are found, loaded, installed and removed, and what one adds.</summary>
[Collection(CliConsoleCollection.Name)]
[Trait("Category", "Unit")]
public sealed class CliExtensionTests : IDisposable
{
    private static readonly Version Cli = new(1, 0, 0);
    private static readonly string SampleType = typeof(SampleCliExtension).FullName!;

    private readonly string _directory = Directory.CreateTempSubdirectory("simplesign-cli-extensions-").FullName;
    private readonly string? _previous = Environment.GetEnvironmentVariable(CliExtensionLoader.DirectoryVariable);

    public CliExtensionTests()
    {
        Environment.SetEnvironmentVariable(CliExtensionLoader.DirectoryVariable, Path.Combine(_directory, "installed"));
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable(CliExtensionLoader.DirectoryVariable, _previous);
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    private static string Manifest(string name = "sample", int contract = CliExtensionContract.Version, string? minCliVersion = null, string? type = null) =>
        $$"""
          { "name": "{{name}}", "assembly": "SimpleSign.Cli.Tests.dll", "type": "{{type ?? SampleType}}", "contract": {{contract}},
            {{(minCliVersion is null ? "" : $"\"minCliVersion\": \"{minCliVersion}\",")}} "version": "1.2.3", "package": "Sample.Extension" }
          """;

    /// <summary>A folder laid out as an installed extension: the manifest and this test assembly, which holds <see cref="SampleCliExtension"/>.</summary>
    private string WriteExtension(string root, string folder, string manifest)
    {
        string directory = Path.Combine(_directory, root, folder);
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, CliExtensionContract.ManifestFileName), manifest);
        File.Copy(typeof(SampleCliExtension).Assembly.Location, Path.Combine(directory, "SimpleSign.Cli.Tests.dll"));
        return Path.Combine(_directory, root);
    }

    /// <summary>A NuGet package of an extension: the <c>cli-extension/</c> folder with the manifest and the assembly.</summary>
    private string WritePackage(string file, string? manifest, params (string Path, string Content)[] extra)
    {
        string path = Path.Combine(_directory, file);
        using var archive = ZipFile.Open(path, ZipArchiveMode.Create);
        archive.CreateEntry("Sample.Extension.nuspec");
        if (manifest is not null)
        {
            WriteEntry(archive, "cli-extension/extension.json", manifest);
            archive.CreateEntryFromFile(typeof(SampleCliExtension).Assembly.Location, "cli-extension/SimpleSign.Cli.Tests.dll");
        }

        foreach (var (entryPath, content) in extra)
        {
            WriteEntry(archive, entryPath, content);
        }

        return path;
    }

    private static void WriteEntry(ZipArchive archive, string path, string content)
    {
        using var writer = new StreamWriter(archive.CreateEntry(path).Open());
        writer.Write(content);
    }

    // ── the loader ──────────────────────────────────────────────────────

    [Fact]
    public void Load_FolderWithAManifest_CreatesTheExtension()
    {
        string root = WriteExtension("a", "sample", Manifest());

        var extension = CliExtensionLoader.Load([root, Path.Combine(_directory, "missing")], Cli).ShouldHaveSingleItem();

        extension.Problem.ShouldBeNull();
        extension.Manifest.Version.ShouldBe("1.2.3");
        var instance = extension.Instance.ShouldNotBeNull();
        instance.Name.ShouldBe("sample");
        // Loaded from the copy in the folder, not from the test's own assembly; the contract is the CLI's.
        instance.ShouldNotBeOfType<SampleCliExtension>();
        instance.Profiles[0].Name.ShouldBe("sample");
    }

    [Fact]
    public void Load_SameNameInTwoFolders_IsLoadedOnceFromTheFirst()
    {
        string first = WriteExtension("first", "sample", Manifest());
        string second = WriteExtension("second", "sample", Manifest());

        var extension = CliExtensionLoader.Load([first, second], Cli).ShouldHaveSingleItem();

        extension.Directory.ShouldStartWith(first);
    }

    [Theory]
    [InlineData("contract", "extension contract")]
    [InlineData("cli", "needs simplesign 9.0")]
    [InlineData("type", "Missing.Type")]
    [InlineData("manifest", "manifest")]
    [InlineData("not-an-extension", "is not an ICliExtension")]
    public void Load_ExtensionThatCannotRun_IsReportedNotThrown(string what, string expected)
    {
        string manifest = what switch
        {
            "contract" => Manifest(contract: CliExtensionContract.Version + 1),
            "cli" => Manifest(minCliVersion: "9.0"),
            "type" => Manifest(type: "Missing.Type"),
            "not-an-extension" => Manifest(type: typeof(CliExtensionTests).FullName),
            _ => "{ not json",
        };
        string root = WriteExtension("broken", "sample", manifest);

        var extension = CliExtensionLoader.Load([root], Cli).ShouldHaveSingleItem();

        extension.Instance.ShouldBeNull();
        extension.Problem.ShouldNotBeNull().ShouldContain(expected, Case.Insensitive);
    }

    [Theory]
    [InlineData("""{ "assembly": "a.dll", "type": "T", "contract": 1 }""", "name")]
    [InlineData("""{ "name": "x", "type": "T", "contract": 1 }""", "assembly")]
    [InlineData("""{ "name": "x", "assembly": "a.dll", "contract": 1 }""", "type")]
    [InlineData("""{ "name": "x", "assembly": "a.dll", "type": "T" }""", "contract")]
    [InlineData("""{ "name": "../x", "assembly": "a.dll", "type": "T", "contract": 1 }""", "name")]
    [InlineData("""{ "name": "x", "assembly": "../a.dll", "type": "T", "contract": 1 }""", "assembly")]
    [InlineData("""{ "name": "x", "assembly": "a.dll", "type": "T", "contract": 1, "minCliVersion": "soon" }""", "minCliVersion")]
    public void ManifestParse_WithoutWhatItNeeds_IsRefused(string json, string about) =>
        Should.Throw<InvalidDataException>(() => ExtensionManifest.Parse(json)).Message.ShouldContain(about);

    // ── installing ──────────────────────────────────────────────────────

    [Fact]
    public void Install_Package_PutsTheExtensionInItsFolderAndReplacesTheCopyThere()
    {
        string target = Path.Combine(_directory, "installed");
        string package = WritePackage("Sample.Extension.1.2.3.nupkg", Manifest());

        var manifest = ExtensionInstaller.Install(File.ReadAllBytes(package), target, Cli);
        File.WriteAllText(Path.Combine(target, "sample", "leftover.txt"), "from an older version");
        ExtensionInstaller.Install(File.ReadAllBytes(package), target, Cli);

        manifest.Name.ShouldBe("sample");
        Directory.GetFiles(Path.Combine(target, "sample")).Select(Path.GetFileName)
            .ShouldBe(["SimpleSign.Cli.Tests.dll", "extension.json"], ignoreOrder: true);
        CliExtensionLoader.Load([target], Cli).ShouldHaveSingleItem().Instance.ShouldNotBeNull();
    }

    [Fact]
    public void Install_PackageThatIsNotAnExtension_IsRefused()
    {
        string package = WritePackage("Some.Library.1.0.0.nupkg", manifest: null, ("lib/net8.0/Some.Library.dll", "x"));

        var ex = Should.Throw<InvalidDataException>(() => ExtensionInstaller.Install(File.ReadAllBytes(package), Path.Combine(_directory, "installed"), Cli));

        ex.Message.ShouldContain("not an extension");
        Directory.Exists(Path.Combine(_directory, "installed", "sample")).ShouldBeFalse();
    }

    [Fact]
    public void Install_PackageForANewerCli_IsRefusedAndNothingIsWritten()
    {
        string package = WritePackage("Sample.Extension.2.0.0.nupkg", Manifest(minCliVersion: "9.0"));

        var ex = Should.Throw<InvalidDataException>(() => ExtensionInstaller.Install(File.ReadAllBytes(package), Path.Combine(_directory, "installed"), Cli));

        ex.Message.ShouldContain("needs simplesign 9.0");
        Directory.Exists(Path.Combine(_directory, "installed", "sample")).ShouldBeFalse();
    }

    [Fact]
    public void Install_PackageWithAFileOutsideItsFolder_IsRefused()
    {
        string package = WritePackage("Sample.Extension.6.6.6.nupkg", Manifest(), ("cli-extension/../../escaped.txt", "x"));

        Should.Throw<InvalidDataException>(() => ExtensionInstaller.Install(File.ReadAllBytes(package), Path.Combine(_directory, "installed"), Cli))
            .Message.ShouldContain("outside its folder");

        File.Exists(Path.Combine(_directory, "escaped.txt")).ShouldBeFalse();
        Directory.Exists(Path.Combine(_directory, "installed", "sample")).ShouldBeFalse();
    }

    [Theory]
    [InlineData(new[] { "0.9.0", "0.12.0", "0.10.1" }, "0.12.0")]
    [InlineData(new[] { "1.0.0", "1.1.0-preview.1" }, "1.0.0")]
    [InlineData(new[] { "1.0.0-rc.1", "1.0.0-rc.2" }, "1.0.0-rc.2")]
    [InlineData(new string[0], null)]
    public void Latest_Versions_PrefersTheHighestStableOne(string[] versions, string? expected) =>
        ExtensionInstaller.Latest(versions).ShouldBe(expected);

    [Fact]
    public void FindPackage_Folder_TakesTheVersionAskedForOrTheLatestAndNotAPackageWithALongerName()
    {
        foreach (string name in new[] { "Sample.Extension.1.0.0.nupkg", "Sample.Extension.1.2.0.nupkg", "Sample.Extension.Tools.9.0.0.nupkg" })
        {
            File.WriteAllText(Path.Combine(_directory, name), "");
        }

        Path.GetFileName(ExtensionInstaller.FindPackage(_directory, "sample.extension", null)).ShouldBe("Sample.Extension.1.2.0.nupkg");
        Path.GetFileName(ExtensionInstaller.FindPackage(_directory, "Sample.Extension", "1.0.0")).ShouldBe("Sample.Extension.1.0.0.nupkg");
        ExtensionInstaller.FindPackage(_directory, "Sample.Extension", "3.0.0").ShouldBeNull();
    }

    // ── the commands ────────────────────────────────────────────────────

    [Fact]
    public async Task ExtensionCommands_InstallListRemove_WorkOnTheUsersFolder()
    {
        string package = WritePackage("Sample.Extension.1.2.3.nupkg", Manifest());

        var (emptyExit, empty) = await RunAsync(null, "extension", "list");
        var (installExit, installed) = await RunAsync(null, "extension", "install", package);
        var (listExit, list) = await RunAsync(null, "extension", "list");
        var (removeExit, removed) = await RunAsync(null, "extension", "remove", "SAMPLE");
        var (missingExit, _) = await RunAsync(null, "extension", "remove", "sample");

        emptyExit.ShouldBe(0, empty);
        empty.ShouldContain("No extension is installed");
        installExit.ShouldBe(0, installed);
        installed.ShouldContain("SHA-512");
        listExit.ShouldBe(0, list);
        list.ShouldContain("Sample.Extension");
        list.ShouldContain("--profile sample");
        removeExit.ShouldBe(0, removed);
        missingExit.ShouldBe(1);
        Directory.Exists(Path.Combine(_directory, "installed", "sample")).ShouldBeFalse();
    }

    [Fact]
    public async Task ExtensionInstall_FromAFolder_TakesTheLatestVersionOfThePackage()
    {
        string source = Path.Combine(_directory, "feed");
        Directory.CreateDirectory(source);
        File.Move(WritePackage("old.nupkg", Manifest().Replace("1.2.3", "1.0.0", StringComparison.Ordinal)), Path.Combine(source, "Sample.Extension.1.0.0.nupkg"));
        File.Move(WritePackage("new.nupkg", Manifest()), Path.Combine(source, "Sample.Extension.1.2.3.nupkg"));

        var (exit, output) = await RunAsync(null, "extension", "install", "Sample.Extension", "--source", source);
        var (missingExit, _) = await RunAsync(null, "extension", "install", "Other.Extension", "--source", source);

        exit.ShouldBe(0, output);
        output.ShouldContain("sample 1.2.3");
        missingExit.ShouldBe(1);
    }

    [Theory]
    [InlineData("http://packages.example/v3-flatcontainer/")]
    [InlineData("ftp://packages.example/")]
    [InlineData("/no/such/folder")]
    public async Task ExtensionInstall_SourceThatIsNeitherAFolderNorHttps_IsRefused(string source) =>
        (await RunAsync(null, "extension", "install", "Sample.Extension", "--source", source)).Exit.ShouldNotBe(0);

    // ── what an extension adds ──────────────────────────────────────────

    [Fact]
    public async Task ConfigureApp_WithAnExtension_AddsItsCommandProfilePoliciesAndTrustedListProfile()
    {
        var extension = new SampleCliExtension();

        var (helloExit, hello) = await RunAsync([extension], "sample", "hello");
        var (profilesExit, profiles) = await RunAsync([extension], "profiles");
        string policy = Path.Combine(_directory, "sample.json");
        var (exportExit, export) = await RunAsync([extension], "policy", "export", "signing", "--preset", "sample", "--output", policy);

        helloExit.ShouldBe(0, hello);
        hello.ShouldContain("hello from the sample extension");
        extension.Context.ShouldNotBeNull().CliVersion.ShouldBe(CliExtensionLoader.CliVersion);
        profilesExit.ShouldBe(0, profiles);
        profiles.ShouldContain("Sample framework");
        profiles.ShouldNotContain("Not the Sandbox");
        exportExit.ShouldBe(0, export);
        File.ReadAllText(policy).ShouldContain("Sample signing policy");
        PolicyPresets.Signing["default"]().Name.ShouldBe(SigningPolicy.Default.Name);
        TrustedListProfiles.IsKnown("sample").ShouldBeTrue();
        TrustedListProfiles.HasBundledSigner("sample").ShouldBeTrue();
        TrustedListProfiles.UnverifiableListGivesNoAnchors("sample").ShouldBeTrue();
    }

    [Fact]
    public async Task ConfigureApp_WithoutExtensions_HasOnlyTheClisOwn()
    {
        await RunAsync([new SampleCliExtension()], "profiles");

        var (exit, output) = await RunAsync(null, "sample", "hello");
        var (_, profiles) = await RunAsync(null, "profiles");

        exit.ShouldNotBe(0, output);
        profiles.ShouldNotContain("Sample framework");
        PolicyPresets.Signing.ContainsKey("sample").ShouldBeFalse();
        PolicyPresets.Validation.ContainsKey("sample").ShouldBeFalse();
        TrustedListProfiles.IsKnown("sample").ShouldBeFalse();
        TrustedListProfiles.IsKnown(null).ShouldBeTrue();
        TrustedListProfiles.HasBundledSigner(null).ShouldBeFalse();
    }

    private static async Task<(int Exit, string Output)> RunAsync(IReadOnlyList<ICliExtension>? extensions, params string[] args)
    {
        var services = new ServiceCollection();
        services.AddSimpleSign();
        services.AddSimpleSignIcpBrasil();
        services.AddSimpleSignGovBr();
        services.AddSimpleSignCades();
        services.AddSimpleSignXades();
        var app = new CommandApp(new SimpleSignServiceRegistry(services));
        Program.ConfigureApp(app, extensions);

        IAnsiConsole originalAnsi = AnsiConsole.Console;
        TextWriter originalOut = Console.Out;
        var ansiText = new StringBuilder();
        using var ansiWriter = new StringWriter(ansiText);
        using var stdout = new StringWriter();
        IAnsiConsole console = AnsiConsole.Create(new AnsiConsoleSettings
        {
            Ansi = AnsiSupport.No,
            ColorSystem = ColorSystemSupport.NoColors,
            Interactive = InteractionSupport.No,
            Out = new AnsiConsoleOutput(ansiWriter),
        });
        console.Profile.Width = 240;
        AnsiConsole.Console = console;
        Console.SetOut(stdout);
        try
        {
            int exit = await Program.RunWithAsync(app, args);
            return (exit, stdout.ToString() + ansiText);
        }
        finally
        {
            AnsiConsole.Console = originalAnsi;
            Console.SetOut(originalOut);
        }
    }
}
