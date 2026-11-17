using System.Reflection;
using SimpleSign.Cli.Extensibility;
using Spectre.Console.Cli;

namespace SimpleSign.Cli.Extensions;

/// <summary>
/// The command line of a pass-through command (<see cref="CliPassThroughCommand"/>), put in the form the command
/// receives: its own options first, then <c>--</c>, then the arguments of the standard command it runs. The user types
/// both kinds of options in any order.
/// </summary>
internal static class CliArguments
{
    /// <summary>
    /// <paramref name="args"/> with the options of a pass-through command moved to the front and <c>--</c> before the
    /// rest; unchanged when the line is not such a command, or already has <c>--</c>.
    /// </summary>
    internal static string[] Normalize(string[] args, IEnumerable<CliPassThroughCommand> commands)
    {
        var command = commands.FirstOrDefault(c => StartsWith(args, c.Path));
        if (command is null)
        {
            return args;
        }

        int start = command.Path.Count;
        if (Array.IndexOf(args, "--", start) >= 0)
        {
            return args;
        }

        var options = OptionsOf(command.SettingsType);
        var own = new List<string>();
        var rest = new List<string>();
        for (int i = start; i < args.Length; i++)
        {
            string arg = args[i];
            string name = NameOf(arg);
            if (arg is "--help" or "-h" or "-?")
            {
                own.Add(arg);
            }
            else if (options.TryGetValue(name, out bool takesValue))
            {
                own.Add(arg);
                if (takesValue && name.Length == arg.Length && i + 1 < args.Length)
                {
                    own.Add(args[++i]);
                }
            }
            else
            {
                rest.Add(arg);
            }
        }

        return [.. args.AsSpan(0, start), .. own, "--", .. rest];
    }

    private static bool StartsWith(string[] args, IReadOnlyList<string> path) =>
        args.Length >= path.Count && path.Select((word, i) => string.Equals(args[i], word, StringComparison.OrdinalIgnoreCase)).All(same => same);

    /// <summary>The option of <paramref name="arg"/> without an attached value (<c>--cpf=1</c>, <c>--cpf:1</c>).</summary>
    private static string NameOf(string arg)
    {
        if (!arg.StartsWith('-'))
        {
            return string.Empty;
        }

        int separator = arg.IndexOfAny(['=', ':']);
        return separator < 0 ? arg : arg[..separator];
    }

    /// <summary>The options the settings declare (<c>--name</c>, <c>-n</c>), and whether each takes a value.</summary>
    private static Dictionary<string, bool> OptionsOf(Type settings)
    {
        var options = new Dictionary<string, bool>(StringComparer.Ordinal);
        foreach (var property in settings.GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (property.GetCustomAttribute<CommandOptionAttribute>() is not { } option)
            {
                continue;
            }

            bool takesValue = option.ValueName is not null;
            foreach (string name in option.LongNames)
            {
                options["--" + name] = takesValue;
            }

            foreach (string name in option.ShortNames)
            {
                options["-" + name] = takesValue;
            }
        }

        return options;
    }
}
