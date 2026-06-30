using Microsoft.Extensions.DependencyInjection;
using Spectre.Console.Cli;

namespace SimpleSign.Cli;

internal sealed class SimpleSignTypeRegistrar(IServiceCollection services) : ITypeRegistrar
{
    public ITypeResolver Build() => new SimpleSignTypeResolver(services.BuildServiceProvider());

    public void Register(Type service, Type implementation) => services.AddSingleton(service, implementation);

    public void RegisterInstance(Type service, object implementation) => services.AddSingleton(service, implementation);

    public void RegisterLazy(Type service, Func<object> factory) => services.AddSingleton(service, _ => factory());

    private sealed class SimpleSignTypeResolver(IServiceProvider provider) : ITypeResolver
    {
        public object? Resolve(Type? type) => type is null ? null : provider.GetService(type);
    }
}
