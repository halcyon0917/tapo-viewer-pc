using System.Net;
using TapoViewer.Core.Rtsp;
using TapoViewer.Core.Security;

namespace TapoViewer.Core.Tests;

public sealed class HostGuardTests
{
    [Fact]
    public void Pins_a_private_literal_address()
    {
        var endpoint = HostGuard.Pin("192.168.1.50", 554);

        Assert.Equal(IPAddress.Parse("192.168.1.50"), endpoint.Address);
        Assert.Equal(554, endpoint.Port);
        Assert.Equal("192.168.1.50:554", endpoint.ToString());
    }

    [Fact]
    public void Refuses_a_public_literal_address()
    {
        var ex = Assert.Throws<UntrustedHostException>(() => HostGuard.Pin("8.8.8.8", 554));
        Assert.Contains("8.8.8.8", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Brackets_ipv6_for_uri_use()
    {
        var endpoint = HostGuard.Pin("fd00::5", 554);
        Assert.Equal("[fd00::5]", endpoint.UriHost);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(65536)]
    public void Rejects_out_of_range_ports(int port)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => HostGuard.Pin("192.168.1.50", port));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Rejects_blank_hosts(string host)
    {
        Assert.Throws<ArgumentException>(() => HostGuard.Pin(host, 554));
    }

    // --- Camera-supplied stream URIs (the ONVIF SSRF surface) ---

    [Fact]
    public void Accepts_a_stream_uri_pointing_at_the_same_camera()
    {
        var pinned = HostGuard.Pin("192.168.1.50", 2020);
        var result = HostGuard.EnsureSameDevice(pinned, new Uri("rtsp://192.168.1.50:554/stream1"));

        Assert.Equal(IPAddress.Parse("192.168.1.50"), result.Address);
        Assert.Equal(554, result.Port);
    }

    [Fact]
    public void Refuses_a_stream_uri_redirected_to_another_lan_host()
    {
        // The redirect target is itself a private address, so the private-range policy alone
        // would wave it through. This is exactly why same-device identity is checked separately:
        // a compromised camera must not be able to point us at the NAS next to it.
        var pinned = HostGuard.Pin("192.168.1.50", 2020);

        var ex = Assert.Throws<UntrustedHostException>(
            () => HostGuard.EnsureSameDevice(pinned, new Uri("rtsp://192.168.1.99:554/stream1")));

        Assert.Contains("192.168.1.99", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Refuses_a_stream_uri_redirected_to_the_internet()
    {
        var pinned = HostGuard.Pin("192.168.1.50", 2020);

        Assert.Throws<UntrustedHostException>(
            () => HostGuard.EnsureSameDevice(pinned, new Uri("rtsp://203.0.113.7:554/stream1")));
    }

    [Theory]
    [InlineData("http://192.168.1.50/stream1")]
    [InlineData("file://192.168.1.50/stream1")]
    public void Refuses_non_rtsp_schemes(string uri)
    {
        var pinned = HostGuard.Pin("192.168.1.50", 2020);

        var ex = Assert.Throws<UntrustedHostException>(
            () => HostGuard.EnsureSameDevice(pinned, new Uri(uri)));

        Assert.Contains("rtsp", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Falls_back_to_the_pinned_port_when_the_uri_omits_one()
    {
        var pinned = new PinnedEndpoint("192.168.1.50", IPAddress.Parse("192.168.1.50"), 554);
        var result = HostGuard.EnsureSameDevice(pinned, new Uri("rtsp://192.168.1.50/stream1"));

        Assert.Equal(554, result.Port);
    }
}

public sealed class RtspTargetTests
{
    [Theory]
    [InlineData(StreamQuality.High, "/stream1")]
    [InlineData(StreamQuality.Standard, "/stream2")]
    public void Maps_quality_to_the_tapo_stream_path(StreamQuality quality, string expected)
    {
        var target = new RtspTarget(HostGuard.Pin("192.168.1.50", 554), quality);
        Assert.Equal(expected, target.Path);
    }

    [Fact]
    public void Never_embeds_credentials_in_the_uri()
    {
        var target = new RtspTarget(HostGuard.Pin("192.168.1.50", 554), StreamQuality.High);
        var uri = target.ToUri();

        Assert.Empty(uri.UserInfo);
        Assert.Equal("rtsp://192.168.1.50:554/stream1", uri.ToString());
    }

    [Fact]
    public void String_form_is_safe_to_log()
    {
        var target = new RtspTarget(HostGuard.Pin("192.168.1.50", 554), StreamQuality.Standard);
        Assert.Equal("rtsp://192.168.1.50:554/stream2", target.ToString());
    }
}
