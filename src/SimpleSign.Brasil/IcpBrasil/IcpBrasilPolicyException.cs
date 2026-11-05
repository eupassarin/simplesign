namespace SimpleSign.Brasil.IcpBrasil;

/// <summary>
/// The signature cannot be made under the requested ICP-Brasil policy — typically because no
/// version of it accepts the root of the signer's certificate (e.g. an AC Raiz v12 certificate
/// with a policy issued before v12).
/// </summary>
public sealed class IcpBrasilPolicyException : Exception
{
    /// <summary>Creates the exception.</summary>
    public IcpBrasilPolicyException()
    {
    }

    /// <summary>Creates the exception with a message.</summary>
    /// <param name="message">The reason.</param>
    public IcpBrasilPolicyException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a message and an inner exception.</summary>
    /// <param name="message">The reason.</param>
    /// <param name="innerException">The cause.</param>
    public IcpBrasilPolicyException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
