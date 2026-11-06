namespace SimpleSign.Core.Crypto;

/// <summary>Factory for creating <see cref="ITimestampClient"/> instances bound to a specific TSA URL.</summary>
public interface ITimestampClientFactory
{
    /// <summary>Creates a timestamp client for the given TSA URL.</summary>
    ITimestampClient Create(string tsaUrl);
}
