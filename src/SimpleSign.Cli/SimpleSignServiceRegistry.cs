using Microsoft.Extensions.DependencyInjection;
using Spectre.Console.Cli;

namespace SimpleSign.Cli;

internal sealed class SimpleSignServiceRegistry(IServiceCollection services) : ITypeRegistrar
{
    public ITypeResolver Build() => new ServiceRegistryResolver(services.BuildServiceProvider());

    public void Register(Type service, Type implementation) => services.AddSingleton(service, implementation);

    public void RegisterInstance(Type service, object implementation) => services.AddSingleton(service, implementation);

    public void RegisterLazy(Type service, Func<object> factory) => services.AddSingleton(service, _ => factory());

    private sealed class ServiceRegistryResolver(IServiceProvider provider) : ITypeResolver
    {
        public object? Resolve(Type? type) => type is null ? null : provider.GetService(type);
    }
}
