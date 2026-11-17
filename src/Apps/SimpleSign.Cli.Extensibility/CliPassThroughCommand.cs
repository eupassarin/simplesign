namespace SimpleSign.Cli.Extensibility;

/// <summary>
/// A command of an extension that takes options of its own and hands every other argument to a standard command
/// (<see cref="CliExtensionContext.SignAsync"/>). Declaring it lets the user type the two kinds of options in any
/// order: before the command line is parsed, the CLI moves the options of <paramref name="SettingsType"/> to the front
/// and puts <c>--</c> before the rest, the form the command receives.
/// </summary>
/// <param name="Path">The words of the command, e.g. <c>["brasil", "sign"]</c>.</param>
/// <param name="SettingsType">The settings of the command: its <c>[CommandOption]</c> properties are its own options.</param>
public sealed record CliPassThroughCommand(IReadOnlyList<string> Path, Type SettingsType);
