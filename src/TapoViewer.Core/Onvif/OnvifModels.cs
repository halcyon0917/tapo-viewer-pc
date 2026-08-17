namespace TapoViewer.Core.Onvif;

/// <summary>Service endpoints a device advertises via <c>GetCapabilities</c>.</summary>
/// <remarks>
/// Each URI is validated to point back at the device itself before it is ever used; a device
/// does not get to redirect us elsewhere on the LAN. Any of these may be
/// <see langword="null"/> — a fixed camera has no PTZ service, and not every model exposes
/// events.
/// </remarks>
public sealed record OnvifCapabilities(Uri? Media, Uri? Ptz, Uri? Events)
{
    public bool SupportsPtz => Ptz is not null;

    public bool SupportsEvents => Events is not null;
}

/// <summary>A media profile: the handle used to request a stream or drive PTZ.</summary>
public sealed record OnvifProfile(string Token, string Name)
{
    public override string ToString() => $"{Name} ({Token})";
}

/// <summary>A stored PTZ position.</summary>
public sealed record OnvifPreset(string Token, string Name)
{
    public override string ToString() => Name;
}

/// <summary>A normalised PTZ velocity; each component is clamped to [-1, 1].</summary>
public readonly record struct PtzVelocity(double Pan, double Tilt, double Zoom)
{
    public static PtzVelocity Clamped(double pan, double tilt, double zoom) => new(
        Math.Clamp(pan, -1.0, 1.0),
        Math.Clamp(tilt, -1.0, 1.0),
        Math.Clamp(zoom, -1.0, 1.0));
}

/// <summary>A motion (or other) notification pulled from the device's event service.</summary>
public sealed record OnvifEvent(string Topic, bool IsMotionDetected, DateTimeOffset ReceivedUtc)
{
    public bool IsMotionStart => IsMotionDetected;
}

/// <summary>An active pull-point event subscription.</summary>
public sealed record OnvifSubscription(Uri Endpoint, DateTimeOffset ExpiresUtc);

/// <summary>Raised when the device rejects a request or answers unusably.</summary>
public sealed class OnvifException : Exception
{
    public OnvifException(string message) : base(message)
    {
    }

    public OnvifException(string message, Exception inner) : base(message, inner)
    {
    }
}

/// <summary>Raised specifically when the camera account credentials are wrong.</summary>
public sealed class OnvifAuthenticationException : Exception
{
    public OnvifAuthenticationException(string message) : base(message)
    {
    }
}
