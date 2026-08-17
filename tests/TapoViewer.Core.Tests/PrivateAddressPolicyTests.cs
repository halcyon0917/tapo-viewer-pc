using System.Net;
using TapoViewer.Core.Security;

namespace TapoViewer.Core.Tests;

public sealed class PrivateAddressPolicyTests
{
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("10.0.0.1")]
    [InlineData("10.255.255.255")]
    [InlineData("192.168.1.50")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.254")]
    [InlineData("169.254.10.20")]
    [InlineData("::1")]
    [InlineData("fd00::1")]
    [InlineData("fc00::1")]
    [InlineData("fe80::1")]
    public void Allows_private_and_local_addresses(string address)
    {
        Assert.True(PrivateAddressPolicy.IsAllowed(IPAddress.Parse(address)));
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("1.1.1.1")]
    [InlineData("203.0.113.7")]
    [InlineData("100.64.0.1")]     // CGNAT is not our LAN
    [InlineData("172.15.0.1")]     // just below the RFC1918 block
    [InlineData("172.32.0.1")]     // just above it
    [InlineData("192.167.1.1")]    // near-miss on 192.168/16
    [InlineData("192.169.1.1")]
    [InlineData("2606:4700::1111")]
    public void Rejects_public_addresses(string address)
    {
        Assert.False(PrivateAddressPolicy.IsAllowed(IPAddress.Parse(address)));
    }

    [Fact]
    public void Rejects_public_address_smuggled_as_ipv4_mapped_ipv6()
    {
        // ::ffff:8.8.8.8 is a public v4 address wearing a v6 costume. If normalisation were
        // missing, this would fall through the v6 branch and be treated as "not ULA, reject"
        // by luck rather than by design — or worse, be accepted. Pin the behaviour.
        Assert.False(PrivateAddressPolicy.IsAllowed(IPAddress.Parse("::ffff:8.8.8.8")));
    }

    [Fact]
    public void Allows_private_address_expressed_as_ipv4_mapped_ipv6()
    {
        Assert.True(PrivateAddressPolicy.IsAllowed(IPAddress.Parse("::ffff:192.168.1.5")));
    }

    [Fact]
    public void Rejection_message_names_the_address_and_suggests_a_vpn()
    {
        var message = PrivateAddressPolicy.DescribeRejection(IPAddress.Parse("8.8.8.8"));

        Assert.Contains("8.8.8.8", message, StringComparison.Ordinal);
        Assert.Contains("VPN", message, StringComparison.Ordinal);
    }

    [Fact]
    public void Null_address_is_rejected_loudly()
    {
        Assert.Throws<ArgumentNullException>(() => PrivateAddressPolicy.IsAllowed(null!));
    }
}
