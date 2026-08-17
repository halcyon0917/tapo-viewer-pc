using System.Text.Json.Serialization;
using TapoViewer.Core.Rtsp;

namespace TapoViewer.Core.Configuration;

/// <summary>
/// Everything the app remembers about one camera — and nothing secret.
/// </summary>
/// <remarks>
/// There is deliberately no password property, and no username either. The camera-account
/// username is stored alongside the password in the OS credential vault, keyed by
/// <see cref="Id"/>. This means the whole config file is non-sensitive: it can be diffed,
/// backed up, or attached to a bug report without leaking access to anyone's cameras.
/// </remarks>
public sealed record CameraProfile
{
    /// <summary>Stable vault key. ASCII letters, digits, '-' and '_' only.</summary>
    public required string Id { get; init; }

    public required string DisplayName { get; init; }

    /// <summary>LAN address or hostname. Validated against the private-network policy on use.</summary>
    public required string Host { get; init; }

    public int RtspPort { get; init; } = RtspTarget.DefaultRtspPort;

    /// <summary>Tapo's ONVIF service port.</summary>
    public int OnvifPort { get; init; } = 2020;

    public StreamQuality PreferredQuality { get; init; } = StreamQuality.High;

    public bool MotionEventsEnabled { get; init; }

    [JsonIgnore]
    public bool IsValid => Validate() is null;

    /// <summary>Returns an error message, or <see langword="null"/> when the profile is usable.</summary>
    public string? Validate()
    {
        if (string.IsNullOrWhiteSpace(Id) || !IsValidId(Id))
        {
            return "Camera id must be non-empty and contain only letters, digits, '-' or '_'.";
        }

        if (string.IsNullOrWhiteSpace(DisplayName))
        {
            return "Camera name must not be empty.";
        }

        if (string.IsNullOrWhiteSpace(Host))
        {
            return "Camera address must not be empty.";
        }

        if (RtspPort is < 1 or > 65535)
        {
            return "RTSP port must be between 1 and 65535.";
        }

        if (OnvifPort is < 1 or > 65535)
        {
            return "ONVIF port must be between 1 and 65535.";
        }

        return null;
    }

    public static bool IsValidId(string id)
    {
        if (string.IsNullOrEmpty(id))
        {
            return false;
        }

        foreach (var c in id)
        {
            if (!char.IsAsciiLetterOrDigit(c) && c != '-' && c != '_')
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Generates a fresh collision-resistant id that satisfies <see cref="IsValidId"/>.</summary>
    public static string NewId() => $"cam-{Guid.NewGuid():N}";
}
