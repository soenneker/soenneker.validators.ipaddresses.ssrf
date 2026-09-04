using System;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using Soenneker.Validators.IpAddresses.Ssrf.Abstract;

namespace Soenneker.Validators.IpAddresses.Ssrf;

/// <inheritdoc cref="ISsrfIpAddressValidator" />
public sealed class SsrfIpAddressValidator : Validator.Validator, ISsrfIpAddressValidator
{
    public SsrfIpAddressValidator(ILogger<SsrfIpAddressValidator> logger) : base(logger)
    {
    }

    public bool Validate(string? address)
    {
        if (address is null)
            return false;

        Span<byte> bytes = stackalloc byte[16];

        if (!TryParseLiteral(address, bytes, out AddressFamily family))
            return false;

        return family == AddressFamily.InterNetwork
            ? IsPublicIpv4(bytes[..4])
            : IsPublicIpv6(bytes);
    }

    public bool Validate(IPAddress? address)
    {
        if (address is null)
            return false;

        Span<byte> bytes = stackalloc byte[16];

        if (!address.TryWriteBytes(bytes, out int bytesWritten))
            return false;

        if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.ScopeId != 0)
            return false;

        return IsPublic(address.AddressFamily, bytes[..bytesWritten]);
    }

    private static bool IsPublic(AddressFamily family, ReadOnlySpan<byte> bytes)
    {
        return family switch
        {
            AddressFamily.InterNetwork when bytes.Length == 4 => IsPublicIpv4(bytes),
            AddressFamily.InterNetworkV6 when bytes.Length == 16 => IsPublicIpv6(bytes),
            _ => false
        };
    }

    private static bool IsPublicIpv4(ReadOnlySpan<byte> bytes)
    {
        byte first = bytes[0];
        byte second = bytes[1];
        byte third = bytes[2];

        // Deny non-forwardable, private, shared, loopback, link-local, documentation,
        // benchmarking, multicast, and reserved address space.
        return first != 0
               && first != 10
               && first != 127
               && !(first == 100 && second is >= 64 and <= 127)
               && !(first == 169 && second == 254)
               && !(first == 172 && second is >= 16 and <= 31)
               && !(first == 192 && second == 0 && third == 0)
               && !(first == 192 && second == 0 && third == 2)
               && !(first == 192 && second == 88 && third == 99)
               && !(first == 192 && second == 168)
               && !(first == 198 && second is 18 or 19)
               && !(first == 198 && second == 51 && third == 100)
               && !(first == 203 && second == 0 && third == 113)
               && first < 224;
    }

    private static bool IsPublicIpv6(ReadOnlySpan<byte> bytes)
    {
        // IPv4-mapped (::ffff:0:0/96) and IPv4-compatible (::/96) addresses can
        // otherwise conceal an IPv4 destination. Classify their suffix in place.
        bool isIpv4Mapped = bytes[..10].IndexOfAnyExcept((byte)0) < 0
                            && bytes[10] == 0xff
                            && bytes[11] == 0xff;
        bool isIpv4Compatible = bytes[..12].IndexOfAnyExcept((byte)0) < 0;

        if (isIpv4Mapped || isIpv4Compatible)
            return IsPublicIpv4(bytes[12..]);

        // Unique-local (fc00::/7).
        if ((bytes[0] & 0xfe) == 0xfc)
            return false;

        // Only the currently allocated IANA global-unicast range (2000::/3) is allowed.
        if ((bytes[0] & 0xe0) != 0x20)
            return false;

        // IETF protocol assignments (2001::/23), documentation (2001:db8::/32 and
        // 3fff::/20), and deprecated 6to4 (2002::/16) are not ordinary destinations.
        if ((bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] < 0x02)
            || (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d && bytes[3] == 0xb8)
            || (bytes[0] == 0x20 && bytes[1] == 0x02))
        {
            return false;
        }

        return !(bytes[0] == 0x3f && bytes[1] == 0xff && (bytes[2] & 0xf0) == 0);
    }

    private static bool TryParseLiteral(ReadOnlySpan<char> value, Span<byte> bytes, out AddressFamily family)
    {
        family = AddressFamily.Unknown;

        if (value.IsEmpty || value.Length > 45 || value.IndexOf('%') >= 0)
            return false;

        if (value.IndexOf(':') < 0)
        {
            if (!TryParseIpv4(value, bytes))
                return false;

            family = AddressFamily.InterNetwork;
            return true;
        }

        Span<ushort> groups = stackalloc ushort[8];
        int compressionIndex = value.IndexOf("::".AsSpan());
        int groupCount;

        if (compressionIndex < 0)
        {
            if (!TryParseIpv6Section(value, groups, out groupCount) || groupCount != 8)
                return false;
        }
        else
        {
            ReadOnlySpan<char> remainder = value[(compressionIndex + 2)..];

            if (remainder.IndexOf("::".AsSpan()) >= 0
                || !TryParseIpv6Section(value[..compressionIndex], groups, out int leftCount)
                || !TryParseIpv6Section(remainder, groups[leftCount..], out int rightCount)
                || leftCount + rightCount >= 8)
            {
                return false;
            }

            groups.Slice(leftCount, rightCount).CopyTo(groups[(8 - rightCount)..]);
            groups.Slice(leftCount, 8 - leftCount - rightCount).Clear();
            groupCount = 8;
        }

        for (int i = 0; i < groupCount; i++)
        {
            bytes[i * 2] = (byte)(groups[i] >> 8);
            bytes[(i * 2) + 1] = (byte)groups[i];
        }

        family = AddressFamily.InterNetworkV6;
        return true;
    }

    private static bool TryParseIpv6Section(ReadOnlySpan<char> section, Span<ushort> groups, out int count)
    {
        count = 0;

        if (section.IsEmpty)
            return true;

        while (true)
        {
            int separatorIndex = section.IndexOf(':');
            ReadOnlySpan<char> token = separatorIndex < 0 ? section : section[..separatorIndex];

            if (token.IsEmpty || count >= groups.Length)
                return false;

            if (token.IndexOf('.') >= 0)
            {
                if (separatorIndex >= 0 || count > groups.Length - 2)
                    return false;

                Span<byte> ipv4 = stackalloc byte[4];

                if (!TryParseIpv4(token, ipv4))
                    return false;

                groups[count++] = (ushort)((ipv4[0] << 8) | ipv4[1]);
                groups[count++] = (ushort)((ipv4[2] << 8) | ipv4[3]);
                return true;
            }

            if (!TryParseHexGroup(token, out groups[count++]))
                return false;

            if (separatorIndex < 0)
                return true;

            section = section[(separatorIndex + 1)..];
        }
    }

    private static bool TryParseHexGroup(ReadOnlySpan<char> token, out ushort result)
    {
        result = 0;

        if (token.IsEmpty || token.Length > 4)
            return false;

        foreach (char character in token)
        {
            int digit = character switch
            {
                >= '0' and <= '9' => character - '0',
                >= 'a' and <= 'f' => character - 'a' + 10,
                >= 'A' and <= 'F' => character - 'A' + 10,
                _ => -1
            };

            if (digit < 0)
                return false;

            result = (ushort)((result << 4) | digit);
        }

        return true;
    }

    private static bool TryParseIpv4(ReadOnlySpan<char> value, Span<byte> bytes)
    {
        for (int part = 0; part < 4; part++)
        {
            int separatorIndex = value.IndexOf('.');
            bool isLast = part == 3;

            if (isLast == (separatorIndex >= 0))
                return false;

            ReadOnlySpan<char> token = separatorIndex < 0 ? value : value[..separatorIndex];

            // Reject leading zeroes to avoid octal and other legacy-form ambiguity.
            if (token.IsEmpty || token.Length > 3 || (token.Length > 1 && token[0] == '0'))
                return false;

            int parsed = 0;

            foreach (char character in token)
            {
                if (character is < '0' or > '9')
                    return false;

                parsed = (parsed * 10) + character - '0';
            }

            if (parsed > byte.MaxValue)
                return false;

            bytes[part] = (byte)parsed;

            if (!isLast)
                value = value[(separatorIndex + 1)..];
        }

        return true;
    }
}
