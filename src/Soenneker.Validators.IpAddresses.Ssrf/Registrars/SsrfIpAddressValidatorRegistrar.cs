using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Soenneker.Validators.IpAddresses.Ssrf.Abstract;

namespace Soenneker.Validators.IpAddresses.Ssrf.Registrars;

/// <summary>
/// IP Address validation for SSRF
/// </summary>
public static class SsrfIpAddressValidatorRegistrar
{
    /// <summary>
    /// Adds <see cref="ISsrfIpAddressValidator"/> as a singleton service. <para/>
    /// </summary>
    /// <param name="services">Service collection that receives the registration.</param>
    /// <returns>The same service collection, so additional registrations can be chained.</returns>
    public static IServiceCollection AddSsrfIpAddressValidatorAsSingleton(this IServiceCollection services)
    {
        services.TryAddSingleton<ISsrfIpAddressValidator, SsrfIpAddressValidator>();

        return services;
    }

    /// <summary>
    /// Adds <see cref="ISsrfIpAddressValidator"/> as a scoped service. <para/>
    /// </summary>
    /// <param name="services">Service collection that receives the registration.</param>
    /// <returns>The same service collection, so additional registrations can be chained.</returns>
    public static IServiceCollection AddSsrfIpAddressValidatorAsScoped(this IServiceCollection services)
    {
        services.TryAddScoped<ISsrfIpAddressValidator, SsrfIpAddressValidator>();

        return services;
    }
}
