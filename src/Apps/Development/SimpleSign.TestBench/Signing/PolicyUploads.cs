using System.Text;
using SimpleSign.Core.Policies;
using SimpleSign.TestBench.Documents;
using SimpleSign.TestBench.Localization;

namespace SimpleSign.TestBench.Signing;

/// <summary>
/// A signing policy chosen in the workbench: the uploaded JSON file, or the library's default when none was
/// uploaded. <see cref="Error"/> says why an uploaded file could not be read (the policy is then the default).
/// </summary>
public sealed record SigningPolicyInput(SigningPolicy Policy, bool Uploaded, string? Error = null)
{
    /// <summary>The library's default signing policy.</summary>
    public static SigningPolicyInput Default { get; } = new(SigningPolicy.Default, false);
}

/// <summary>Reads the signing and validation policies the user uploaded as JSON (root SigningConstraints / ValidationConstraints).</summary>
internal static class PolicyUploads
{
    /// <summary>The file name the generated code and CLI command load a signing policy from.</summary>
    public const string SigningFileName = "signing-policy.json";

    /// <summary>The file name the generated code and CLI command load a validation policy from.</summary>
    public const string ValidationFileName = "validation-policy.json";

    /// <summary>The signing policy of an upload (null: the default).</summary>
    public static SigningPolicyInput Signing(string? uploadId, DocumentStore documents)
    {
        if (uploadId is null)
        {
            return SigningPolicyInput.Default;
        }

        try
        {
            return new(SigningPolicy.FromJson(Text(uploadId, documents)), true);
        }
        catch (Exception ex) when (ex is InvalidDataException or KeyNotFoundException)
        {
            return new(SigningPolicy.Default, true, ex.Message);
        }
    }

    /// <summary>The validation policy of an upload (null: the default); throws when the file is not a validation policy.</summary>
    public static ValidationPolicy Validation(string? uploadId, DocumentStore documents)
    {
        if (uploadId is null)
        {
            return ValidationPolicy.Default;
        }

        try
        {
            return ValidationPolicy.FromJson(Text(uploadId, documents));
        }
        catch (InvalidDataException ex)
        {
            throw new ArgumentException(L.T("The validation policy cannot be read: {0}", ex.Message), ex);
        }
    }

    /// <summary>The builder call that applies an uploaded signing policy.</summary>
    public static string SigningCode(SigningPolicyInput input) =>
        $".WithSigningPolicy(SigningPolicy.Load(\"{SigningFileName}\")) // {input.Policy.Name}";

    private static string Text(string uploadId, DocumentStore documents)
    {
        byte[] content = documents.Get(uploadId).Content;
        // A UTF-8 byte order mark is not JSON.
        return content.AsSpan().StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF])
            ? Encoding.UTF8.GetString(content, 3, content.Length - 3)
            : Encoding.UTF8.GetString(content);
    }
}
