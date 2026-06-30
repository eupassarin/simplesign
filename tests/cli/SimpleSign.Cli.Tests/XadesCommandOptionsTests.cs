using Shouldly;
using SimpleSign.Cli.Commands;

namespace SimpleSign.Cli.Tests;

public sealed class XadesCommandOptionsTests
{
    [Fact]
    public void ValidateCommand_RejectsMissingInput()
    {
        var settings = new XadesSignCommand.Settings { InputPath = "/nonexistent/file.xml" };
        var result = settings.Validate();
        result.Successful.ShouldBeFalse();
        result.Message.ShouldBe("File not found: /nonexistent/file.xml");
    }

    [Fact]
    public void ValidateCommand_AcceptsValidInput()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "<doc/>");
            var settings = new XadesSignCommand.Settings { InputPath = path };
            var result = settings.Validate();
            result.Successful.ShouldBeTrue();
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ValidateCommand_RejectsInvalidLevel()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "<doc/>");
            var settings = new XadesSignCommand.Settings { InputPath = path, Level = "invalid" };
            var result = settings.Validate();
            result.Successful.ShouldBeFalse();
            result.Message.ShouldBe("Invalid level: invalid. Valid: basic, timestamped, longterm, archive");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ValidateCommand_RejectsInvalidForm()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "<doc/>");
            var settings = new XadesSignCommand.Settings { InputPath = path, Form = "invalid" };
            var result = settings.Validate();
            result.Successful.ShouldBeFalse();
            result.Message.ShouldBe("Invalid form: invalid. Valid: enveloped, detached, enveloping");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ValidateCommand_RejectsInvalidHash()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "<doc/>");
            var settings = new XadesSignCommand.Settings { InputPath = path, HashAlgorithm = "MD5" };
            var result = settings.Validate();
            result.Successful.ShouldBeFalse();
            result.Message.ShouldBe("Invalid hash algorithm: MD5. Valid: SHA256, SHA384, SHA512");
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ValidateCommand_RejectsMissingCertFile()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "<doc/>");
            var settings = new XadesSignCommand.Settings
            {
                InputPath = path,
                CertPath = "/nonexistent/cert.pfx"
            };
            var result = settings.Validate();
            result.Successful.ShouldBeFalse();
            result.Message.ShouldBe("Certificate file not found: /nonexistent/cert.pfx");
        }
        finally
        {
            File.Delete(path);
        }
    }
}
