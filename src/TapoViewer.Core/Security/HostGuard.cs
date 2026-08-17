using System.Net;
using System.Net.Sockets;

namespace TapoViewer.Core.Security;

/// <summary>Raised when a host fails the private-network policy.</summary>
public sealed class UntrustedHostException : Exception
{
    public UntrustedHostException(string message) : base(message)
    {
    }

    public UntrustedHostException(string message, Exception inner) : base(message, inner)
    {
    }
}

/// <summary>
/// A host name that has been resolved once, validated, and frozen to a specific IP address.
/// </summary>
/// <remarks>
/// Everything downstream connects to <see cref="Address"/>, never to
/// <see cref="OriginalHost"/>. That is what closes the DNS-rebinding window: if we validated a
/// name and then handed the *name* to libVLC, a second lookup could return a public address and
/// our check would have been decorative.
/// </remarks>
public sealed record PinnedEndpoint(string OriginalHost, IPAddress Address, int Port)
{
    /// <summary>The address in a form safe to embed in a URI (IPv6 needs brackets).</summary>
    public string UriHost => Address.AddressFamily == AddressFamily.InterNetworkV6
        ? $"[{Address}]"
        : Address.ToString();

    public override string ToString() => $"{UriHost}:{Port}";
}

/// <summary>
/// The single gate through which every host must pass before this application will talk to it.
/// </summary>
public static class HostGuard
{
    public static PinnedEndpoint Pin(string host, int port)
        => PinCore(host, port, static h => Dns.GetHostAddresses(h));

    public static async Task<PinnedEndpoint> PinAsync(
        string host,
        int port,
        CancellationToken cancellationToken = default)
    {
        ValidateArguments(host, port);

        if (IPAddress.TryParse(host, out var literal))
        {
            return PinLiteral(host, port, literal);
        }

        IPAddress[] resolved;
        try
        {
            resolved = await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
        }
        catch (SocketException ex)
        {
            throw new UntrustedHostException($"Could not resolve '{host}'.", ex);
        }

        return PinResolved(host, port, resolved);
    }

    private static PinnedEndpoint PinCore(string host, int port, Func<string, IPAddress[]> resolver)
    {
        ValidateArguments(host, port);

        if (IPAddress.TryParse(host, out var literal))
        {
            return PinLiteral(host, port, literal);
        }

        IPAddress[] resolved;
        try
        {
            resolved = resolver(host);
        }
        catch (SocketException ex)
        {
            throw new UntrustedHostException($"Could not resolve '{host}'.", ex);
        }

        return PinResolved(host, port, resolved);
    }

    private static PinnedEndpoint PinLiteral(string host, int port, IPAddress literal)
    {
        if (!PrivateAddressPolicy.IsAllowed(literal))
        {
            throw new UntrustedHostException(PrivateAddressPolicy.DescribeRejection(literal));
        }

        return new PinnedEndpoint(host, literal, port);
    }

    private static PinnedEndpoint PinResolved(string host, int port, IPAddress[] resolved)
    {
        if (resolved.Length == 0)
        {
            throw new UntrustedHostException($"'{host}' did not resolve to any address.");
        }

        // Every answer must be private, not merely the one we intend to use. A name that
        // returns a mix of private and public addresses is either misconfigured or an active
        // rebinding attempt; neither deserves our credentials.
        foreach (var candidate in resolved)
        {
            if (!PrivateAddressPolicy.IsAllowed(candidate))
            {
                throw new UntrustedHostException(
                    $"'{host}' resolves to {candidate}, which is not a private LAN address. " +
                    PrivateAddressPolicy.DescribeRejection(candidate));
            }
        }

        return new PinnedEndpoint(host, resolved[0], port);
    }

    /// <summary>
    /// Verifies that a URI handed to us <i>by a camera</i> still points at that same camera.
    /// </summary>
    /// <remarks>
    /// ONVIF <c>GetStreamUri</c> returns an absolute URI chosen by the device. Treating it as
    /// trusted would hand a compromised camera an SSRF primitive against our own host and LAN.
    /// So: the scheme must be RTSP, and the target address must be the exact address we already
    /// pinned for that device.
    /// </remarks>
    public static readonly string[] RtspSchemes = ["rtsp", "rtsps"];

    /// <summary>Schemes valid for an ONVIF service endpoint advertised by a device.</summary>
    public static readonly string[] OnvifSchemes = ["http", "https"];

    public static PinnedEndpoint EnsureSameDevice(PinnedEndpoint expected, Uri deviceSupplied)
        => EnsureSameDevice(expected, deviceSupplied, RtspSchemes);

    public static PinnedEndpoint EnsureSameDevice(
        PinnedEndpoint expected,
        Uri deviceSupplied,
        IReadOnlyCollection<string> allowedSchemes)
    {
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(deviceSupplied);
        ArgumentNullException.ThrowIfNull(allowedSchemes);

        if (!deviceSupplied.IsAbsoluteUri)
        {
            throw new UntrustedHostException("Camera returned a relative stream URI.");
        }

        var schemeAllowed = false;
        foreach (var scheme in allowedSchemes)
        {
            if (string.Equals(deviceSupplied.Scheme, scheme, StringComparison.OrdinalIgnoreCase))
            {
                schemeAllowed = true;
                break;
            }
        }

        if (!schemeAllowed)
        {
            throw new UntrustedHostException(
                $"Camera returned a '{deviceSupplied.Scheme}' URI; only " +
                $"{string.Join("/", allowedSchemes)} are accepted.");
        }

        var host = deviceSupplied.Host;
        if (!IPAddress.TryParse(host, out var address))
        {
            // A name here is not inherently hostile, but resolving it lets the device steer us
            // at a third party. Resolve it and require it to land on the device itself.
            try
            {
                var resolved = Dns.GetHostAddresses(host);
                address = Array.Find(resolved, candidate => candidate.Equals(expected.Address))
                    ?? throw new UntrustedHostException(
                        $"Camera returned stream host '{host}', which does not resolve to {expected.Address}.");
            }
            catch (SocketException ex)
            {
                throw new UntrustedHostException(
                    $"Camera returned unresolvable stream host '{host}'.", ex);
            }
        }

        if (!address.Equals(expected.Address))
        {
            throw new UntrustedHostException(
                $"Camera at {expected.Address} returned a stream URI pointing at {address}. " +
                "Refusing to follow it.");
        }

        var port = deviceSupplied.IsDefaultPort ? expected.Port : deviceSupplied.Port;
        return new PinnedEndpoint(expected.OriginalHost, expected.Address, port);
    }

    private static void ValidateArguments(string host, int port)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);

        if (port is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(port), port, "Port must be 1-65535.");
        }
    }
}
