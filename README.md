[![](https://img.shields.io/nuget/v/soenneker.validators.ipaddresses.ssrf.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.validators.ipaddresses.ssrf/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.validators.ipaddresses.ssrf/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.validators.ipaddresses.ssrf/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.validators.ipaddresses.ssrf.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.validators.ipaddresses.ssrf/)

# ![](https://user-images.githubusercontent.com/4441470/224455560-91ed3ee7-f510-4041-a8d2-3fc093025112.png) Soenneker.Validators.IpAddresses.Ssrf
### IP address validation for SSRF protection

Determines whether an IPv4 or IPv6 address is publicly routable. Private, loopback,
link-local, carrier-grade NAT, documentation, benchmarking, multicast, reserved,
IPv4-mapped IPv6, and other special-use destinations are handled conservatively.

## Installation

```
dotnet add package Soenneker.Validators.IpAddresses.Ssrf
```

## Usage

```csharp
services.AddSsrfIpAddressValidatorAsSingleton();

ISsrfIpAddressValidator validator =
    serviceProvider.GetRequiredService<ISsrfIpAddressValidator>();

bool isPublic = validator.Validate("8.8.8.8");       // true
bool isPrivate = validator.Validate("192.168.1.10"); // false
bool isLoopback = validator.Validate(IPAddress.Loopback); // false
```

`Validate(string)` accepts unambiguous IP address literals only and performs no
managed allocations. It does not resolve hostnames. Legacy abbreviated, octal, and
hexadecimal IPv4 forms are rejected.
For SSRF-safe HTTP requests, resolve every hostname and validate every returned
address at connection time. Revalidate redirects as well, so DNS rebinding cannot
bypass an earlier check.
