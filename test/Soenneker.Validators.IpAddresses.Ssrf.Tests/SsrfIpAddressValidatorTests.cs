using System;
using System.Net;
using AwesomeAssertions;
using Soenneker.Validators.IpAddresses.Ssrf.Abstract;
using Soenneker.Tests.HostedUnit;

namespace Soenneker.Validators.IpAddresses.Ssrf.Tests;

[ClassDataSource<Host>(Shared = SharedType.PerTestSession)]
public sealed class SsrfIpAddressValidatorTests : HostedUnitTest
{
    private readonly ISsrfIpAddressValidator _validator;

    public SsrfIpAddressValidatorTests(Host host) : base(host)
    {
        _validator = Resolve<ISsrfIpAddressValidator>(true);
    }

    [Test]
    [Arguments("1.1.1.1")]
    [Arguments("8.8.8.8")]
    [Arguments("9.9.9.9")]
    [Arguments("2606:4700:4700::1111")]
    [Arguments("2001:4860:4860::8888")]
    [Arguments("2001:4860:4860:0:0:0:0:8888")]
    [Arguments("::ffff:8.8.8.8")]
    [Arguments("::8.8.8.8")]
    public void Validate_PublicAddress_ReturnsTrue(string value)
    {
        _validator.Validate(value).Should().BeTrue();
        _validator.Validate(IPAddress.Parse(value)).Should().BeTrue();
    }

    [Test]
    [Arguments("0.0.0.0")]
    [Arguments("10.0.0.1")]
    [Arguments("100.64.0.1")]
    [Arguments("100.127.255.255")]
    [Arguments("127.0.0.1")]
    [Arguments("169.254.169.254")]
    [Arguments("172.16.0.1")]
    [Arguments("172.31.255.255")]
    [Arguments("192.0.0.1")]
    [Arguments("192.0.2.1")]
    [Arguments("192.88.99.1")]
    [Arguments("192.168.1.1")]
    [Arguments("198.18.0.1")]
    [Arguments("198.51.100.1")]
    [Arguments("203.0.113.1")]
    [Arguments("224.0.0.1")]
    [Arguments("255.255.255.255")]
    public void Validate_NonPublicIpv4Address_ReturnsFalse(string value)
    {
        _validator.Validate(value).Should().BeFalse();
        _validator.Validate(IPAddress.Parse(value)).Should().BeFalse();
    }

    [Test]
    [Arguments("::")]
    [Arguments("::1")]
    [Arguments("::ffff:127.0.0.1")]
    [Arguments("::127.0.0.1")]
    [Arguments("2001::1")]
    [Arguments("2001:db8::1")]
    [Arguments("2002::1")]
    [Arguments("3fff::1")]
    [Arguments("fc00::1")]
    [Arguments("fdff:ffff::1")]
    [Arguments("fe80::1")]
    [Arguments("ff02::1")]
    public void Validate_NonPublicIpv6Address_ReturnsFalse(string value)
    {
        _validator.Validate(value).Should().BeFalse();
        _validator.Validate(IPAddress.Parse(value)).Should().BeFalse();
    }

    [Test]
    [Arguments(null)]
    [Arguments("")]
    [Arguments("localhost")]
    [Arguments("example.com")]
    [Arguments("not-an-address")]
    [Arguments("01.1.1.1")]
    [Arguments("1.1.1")]
    [Arguments("256.1.1.1")]
    [Arguments("2001:db8:::1")]
    [Arguments("2001::db8::1")]
    [Arguments("2001:db8:0:0:0:0:0")]
    [Arguments("2001:db8:0:0:0:0:0:0:1")]
    [Arguments("2606:4700:4700::1111%1")]
    public void Validate_InvalidLiteral_ReturnsFalse(string? value)
    {
        _validator.Validate(value).Should().BeFalse();
    }

    [Test]
    public void Validate_NullIpAddress_ReturnsFalse()
    {
        _validator.Validate((IPAddress?)null).Should().BeFalse();
    }

    [Test]
    public void Validate_StringLiteral_DoesNotAllocate()
    {
        const string address = "2606:4700:4700::1111";

        // Warm up JIT and static initialization before measuring the hot path.
        _validator.Validate(address).Should().BeTrue();

        long before = GC.GetAllocatedBytesForCurrentThread();
        bool allValid = true;

        for (int i = 0; i < 1_000; i++)
            allValid &= _validator.Validate(address);

        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        allValid.Should().BeTrue();
        allocated.Should().Be(0);
    }
}
