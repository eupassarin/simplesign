namespace SimpleSign.Core;

/// <summary>
/// Base exception for all SimpleSign domain errors.
/// </summary>
public class SimpleSignException : Exception
{
    /// <summary>Creates a new instance with the specified message.</summary>
    public SimpleSignException(string message) : base(message) { }
    /// <summary>Creates a new instance with the specified message and inner exception.</summary>
    public SimpleSignException(string message, Exception innerException) : base(message, innerException) { }
}
