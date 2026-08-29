[![](https://img.shields.io/nuget/v/soenneker.validators.ipaddresses.ssrf.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.validators.ipaddresses.ssrf/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.validators.ipaddresses.ssrf/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.validators.ipaddresses.ssrf/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.validators.ipaddresses.ssrf.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.validators.ipaddresses.ssrf/)

# Soenneker.Validators.IpAddresses.Ssrf

Validates that an IP address is publicly routable and is not a known SSRF target.

## Install

```bash
dotnet add package Soenneker.Validators.IpAddresses.Ssrf
```

## Quick start

```csharp
using Soenneker.Validators.IpAddresses.Ssrf.Registrars;
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection();
var result = services.AddSsrfIpAddressValidatorAsSingleton();
```

Adds `ISsrfIpAddressValidator` as a singleton service.

## What you get

- `ISsrfIpAddressValidator` — Validates that an IP address is publicly routable and is not a known SSRF target.
- `SsrfIpAddressValidatorRegistrar` — IP Address validation for SSRF.

## API at a glance

| API | What it does | Result / important behavior |
| --- | --- | --- |
| `ISsrfIpAddressValidator.Validate(address)` | Determines whether an IP address is publicly routable. | `true` when `address` is a publicly routable IPv4 or IPv6 address; otherwise, `false`. |
| `SsrfIpAddressValidatorRegistrar.AddSsrfIpAddressValidatorAsSingleton(services)` | Adds `ISsrfIpAddressValidator` as a singleton service. | The same service collection, so additional registrations can be chained. |
| `SsrfIpAddressValidatorRegistrar.AddSsrfIpAddressValidatorAsScoped(services)` | Adds `ISsrfIpAddressValidator` as a scoped service. | The same service collection, so additional registrations can be chained. |
