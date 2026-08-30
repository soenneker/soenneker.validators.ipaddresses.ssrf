[![](https://img.shields.io/nuget/v/soenneker.validators.ipaddresses.ssrf.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.validators.ipaddresses.ssrf/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.validators.ipaddresses.ssrf/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.validators.ipaddresses.ssrf/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.validators.ipaddresses.ssrf.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.validators.ipaddresses.ssrf/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.validators.ipaddresses.ssrf/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.validators.ipaddresses.ssrf/actions/workflows/codeql.yml)

# Soenneker.Validators.IpAddresses.Ssrf

Conservatively accepts public IPv4 and IPv6 literals while rejecting private, local, reserved, documentation, transition, and other special-purpose ranges commonly involved in SSRF.

## Install

```bash
dotnet add package Soenneker.Validators.IpAddresses.Ssrf
```

## Registration

```csharp
using Soenneker.Validators.IpAddresses.Ssrf.Registrars;
using Microsoft.Extensions.DependencyInjection;

services.AddSsrfIpAddressValidatorAsSingleton();
```

The validator is stateless. Singleton registration is appropriate for most applications; `AddSsrfIpAddressValidatorAsScoped()` is also available.

## Validate a literal

```csharp
using Soenneker.Validators.IpAddresses.Ssrf.Abstract;

bool publicIpv4 = validator.Validate("8.8.8.8");
bool privateIpv4 = validator.Validate("10.0.0.1");
bool loopbackIpv6 = validator.Validate("::1");

// true, false, false
```

The string overload accepts canonical dotted-decimal IPv4 and standard IPv6 literal forms. It rejects hostnames, IPv4 parts with leading zeroes, IPv6 zone/scope identifiers, malformed compression, and null or empty input. It parses without DNS resolution.

An `IPAddress` overload is available when parsing has already occurred:

```csharp
bool allowed = validator.Validate(resolvedAddress);
```

Scoped IPv6 `IPAddress` instances are rejected when `ScopeId` is nonzero. IPv4-mapped and IPv4-compatible IPv6 addresses are classified using their embedded IPv4 destination, preventing loopback or private IPv4 from being hidden inside IPv6 notation.

## Classification policy

IPv4 rejection includes unspecified, private-use, carrier-grade NAT, loopback, link-local, protocol-assignment, documentation, 6to4-relay, benchmarking, multicast, and reserved ranges.

IPv6 acceptance is restricted to the allocated `2000::/3` global-unicast range, with additional rejection for IETF protocol assignments, documentation blocks, deprecated 6to4, and unique-local addresses. This is deliberately conservative: a globally reachable special-purpose exception may still be rejected.

The policy is implemented as compiled prefix checks based on the [IANA IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry) and [IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry) special-purpose registries. It is not downloaded or updated at runtime.

## Using it in SSRF defenses

This validator is one component, not a complete SSRF defense. For a user-supplied hostname or URL:

1. Restrict schemes and ports.
2. Resolve the hostname and reject the request if any candidate address is disallowed.
3. Ensure the HTTP connection is made to the validated address, not a later unvalidated DNS result.
4. Revalidate every redirect target or disable redirects.
5. Apply destination allowlists where possible.

Validating once and then performing a normal hostname request remains vulnerable to DNS rebinding and time-of-check/time-of-use changes. The result also says nothing about application-layer safety on an otherwise public host.
