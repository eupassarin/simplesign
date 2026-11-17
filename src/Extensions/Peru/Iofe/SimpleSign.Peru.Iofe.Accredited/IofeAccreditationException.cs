namespace SimpleSign.Peru.Iofe.Accredited;

/// <summary>
/// The accredited configuration refused an operation: see <see cref="Refusal"/>. The checks of the signing policy
/// (revocation, validity, key usage, algorithms, trust) keep throwing <c>SigningException</c> with its <c>Reason</c>.
/// </summary>
public sealed class IofeAccreditationException : Exception
{
    /// <summary>Creates the exception.</summary>
    public IofeAccreditationException()
    {
    }

    /// <summary>Creates the exception with a message.</summary>
    /// <param name="message">The message.</param>
    public IofeAccreditationException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a message and its cause.</summary>
    /// <param name="message">The message.</param>
    /// <param name="innerException">The cause.</param>
    public IofeAccreditationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Creates the exception with a message and the refusal.</summary>
    /// <param name="message">The message.</param>
    /// <param name="refusal">Why the operation was refused.</param>
    public IofeAccreditationException(string message, IofeRefusal refusal)
        : base(message)
    {
        Refusal = refusal;
    }

    /// <summary>Creates the exception with a message, the refusal and its cause.</summary>
    /// <param name="message">The message.</param>
    /// <param name="refusal">Why the operation was refused.</param>
    /// <param name="innerException">The cause.</param>
    public IofeAccreditationException(string message, IofeRefusal refusal, Exception innerException)
        : base(message, innerException)
    {
        Refusal = refusal;
    }

    /// <summary>Why the operation was refused.</summary>
    public IofeRefusal Refusal { get; }
}
