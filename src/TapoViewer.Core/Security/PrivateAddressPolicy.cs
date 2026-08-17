using System.Net;
using System.Net.Sockets;

namespace TapoViewer.Core.Security;

/// <summary>
/// Decides whether an IP address is somewhere this application is willing to send camera
/// credentials.
/// </summary>
/// <remarks>
/// Tapo's RTSP has no TLS: credentials use Digest auth but the video itself is cleartext, and
/// a Digest exchange with a hostile server still leaks a crackable challenge response. The only
/// safe posture is to refuse to speak RTSP to anything outside the local network.
///
/// This is enforced centrally rather than at the UI, because hosts reach us from two untrusted
/// directions: what the user types, and what a <i>camera</i> tells us in an ONVIF
/// <c>GetStreamUri</c> response. The second is the dangerous one — a compromised or spoofed
/// camera can answer with any URI it likes, and without this check we would happily dial it.
/// </remarks>
public static class PrivateAddressPolicy
{
    public static bool IsAllowed(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        // Normalise ::ffff:203.0.113.7 so an attacker cannot smuggle a public v4 address
        // past the v4 checks by wrapping it in a v6 envelope.
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        return address.AddressFamily switch
        {
            AddressFamily.InterNetwork => IsAllowedV4(address),
            AddressFamily.InterNetworkV6 => IsAllowedV6(address),
            _ => false,
        };
    }

    /// <summary>Human-readable reason for a rejection, for error messages and logs.</summary>
    public static string DescribeRejection(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        return $"{address} is not a private LAN address. This application only connects to " +
               "cameras on your local network (10.x, 172.16-31.x, 192.168.x, 169.254.x, " +
               "IPv6 unique-local or link-local). Use a VPN such as Tailscale or WireGuard " +
               "for remote access instead of exposing the camera to the internet.";
    }

    private static bool IsAllowedV4(IPAddress address)
    {
        Span<byte> octets = stackalloc byte[4];
        if (!address.TryWriteBytes(octets, out var written) || written != 4)
        {
            return false;
        }

        return octets[0] switch
        {
            127 => true,                                        // 127.0.0.0/8   loopback
            10 => true,                                         // 10.0.0.0/8    RFC1918
            192 when octets[1] == 168 => true,                   // 192.168.0.0/16 RFC1918
            172 when octets[1] >= 16 && octets[1] <= 31 => true, // 172.16.0.0/12 RFC1918
            169 when octets[1] == 254 => true,                   // 169.254.0.0/16 link-local
            _ => false,
        };
    }

    private static bool IsAllowedV6(IPAddress address)
    {
        if (IPAddress.IPv6Loopback.Equals(address) || address.IsIPv6LinkLocal)
        {
            return true;
        }

        Span<byte> bytes = stackalloc byte[16];
        if (!address.TryWriteBytes(bytes, out var written) || written != 16)
        {
            return false;
        }

        // fc00::/7 unique-local.
        return (bytes[0] & 0xFE) == 0xFC;
    }
}
