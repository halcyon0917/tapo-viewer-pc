using TapoViewer.Core.Security;

namespace TapoViewer.Core.Rtsp;

public enum StreamQuality
{
    /// <summary>Tapo <c>/stream1</c> — full resolution.</summary>
    High,

    /// <summary>Tapo <c>/stream2</c> — reduced resolution, for grid views and weak links.</summary>
    Standard,
}

/// <summary>
/// A validated, credential-free RTSP address.
/// </summary>
/// <remarks>
/// The obvious way to build these is <c>rtsp://user:pass@host/stream1</c>, and it is a mistake.
/// A URI with embedded credentials ends up in log files, exception messages, crash dumps,
/// libVLC's own verbose output, and — worst — the child process command line, where <i>any</i>
/// local user can read it out of the process list with no privileges at all.
///
/// So this type structurally cannot carry a password: there is nowhere to put one. Credentials
/// travel to the decoder over a separate private channel.
/// </remarks>
public sealed record RtspTarget(PinnedEndpoint Endpoint, StreamQuality Quality)
{
    public const int DefaultRtspPort = 554;

    public string Path => Quality == StreamQuality.High ? "/stream1" : "/stream2";

    public Uri ToUri()
    {
        var builder = new UriBuilder
        {
            Scheme = "rtsp",
            Host = Endpoint.Address.ToString(),
            Port = Endpoint.Port,
            Path = Path,
        };

        var uri = builder.Uri;

        // Belt and braces: assert the invariant this type exists to guarantee, so a future
        // refactor that reintroduces userinfo fails loudly here rather than leaking quietly.
        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            throw new InvalidOperationException("RTSP target must never carry embedded credentials.");
        }

        return uri;
    }

    /// <summary>Safe for logs and on-screen display: contains no secret.</summary>
    public override string ToString() => $"rtsp://{Endpoint.UriHost}:{Endpoint.Port}{Path}";
}
