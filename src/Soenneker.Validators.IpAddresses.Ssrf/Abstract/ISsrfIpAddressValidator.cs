using System.Net;
using Soenneker.Validators.Validator.Abstract;

namespace Soenneker.Validators.IpAddresses.Ssrf.Abstract;

/// <summary>
/// Validates that an IP address is publicly routable and is not a known SSRF target.
/// </summary>
public interface ISsrfIpAddressValidator : IValidator
{
    /// <summary>
    /// Determines whether an IP address is publicly routable.
    /// </summary>
    /// <param name="address">The address to validate.</param>
    /// <returns>
    /// <c>true</c> when <paramref name="address"/> is a publicly routable IPv4 or IPv6 address;
    /// otherwise, <c>false</c>.
    /// </returns>
    bool Validate(IPAddress? address);

    /// <summary>
    /// Parses an IP address literal and determines whether it is publicly routable.
    /// </summary>
    /// <param name="address">The IPv4 or IPv6 address literal to validate.</param>
    /// <returns>
    /// <c>true</c> when <paramref name="address"/> is a valid, publicly routable IP address literal;
    /// otherwise, <c>false</c>.
    /// </returns>
    /// <remarks>Hostnames are not resolved by this method.</remarks>
    bool Validate(string? address);
}
