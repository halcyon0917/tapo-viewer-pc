using TapoViewer.Core.Onvif;
using TapoViewer.Core.Security;

namespace TapoViewer.App.Services;

/// <summary>Outcome of a connection test, in a form the editor dialog can show directly.</summary>
public sealed record CameraTestResult(
    bool Success,
    string Message,
    bool SupportsPtz = false,
    bool SupportsEvents = false,
    int? RtspPort = null);

/// <summary>
/// Verifies a camera's address and credentials before anything is saved.
/// </summary>
/// <remarks>
/// Without this, a typo in the address or password produces a saved camera that silently never
/// connects, and the user has no way to tell which field was wrong. Testing first also tells us
/// whether PTZ and event services exist, so the saved profile reflects what the camera actually
/// offers instead of what was guessed.
/// </remarks>
public static class CameraTester
{
    public static async Task<CameraTestResult> TestAsync(
        string host,
        int onvifPort,
        string userName,
        Secret password,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var endpoint = await HostGuard.PinAsync(host, onvifPort, cancellationToken).ConfigureAwait(false);

            using var client = new OnvifClient(endpoint, userName, password);
            var capabilities = await client.GetCapabilitiesAsync(cancellationToken).ConfigureAwait(false);

            if (capabilities.Media is null)
            {
                return new CameraTestResult(false, "Connected, but the camera advertises no media service.");
            }

            var profiles = await client.GetProfilesAsync(capabilities.Media, cancellationToken)
                .ConfigureAwait(false);

            var target = await client.GetStreamUriAsync(
                capabilities.Media,
                profiles[0].Token,
                Core.Rtsp.StreamQuality.High,
                cancellationToken).ConfigureAwait(false);

            var details = new List<string>
            {
                $"{profiles.Count} stream profile(s)",
                capabilities.SupportsPtz ? "PTZ supported" : "no PTZ (fixed camera)",
                capabilities.SupportsEvents ? "motion events supported" : "no motion events",
            };

            return new CameraTestResult(
                true,
                $"Success — {string.Join(", ", details)}. Stream: {target}",
                capabilities.SupportsPtz,
                capabilities.SupportsEvents,
                target.Endpoint.Port);
        }
        catch (OnvifAuthenticationException ex)
        {
            return new CameraTestResult(false, ex.Message);
        }
        catch (UntrustedHostException ex)
        {
            return new CameraTestResult(false, ex.Message);
        }
        catch (OnvifException ex)
        {
            return new CameraTestResult(false, ex.Message);
        }
        catch (OperationCanceledException)
        {
            return new CameraTestResult(false, "Test cancelled.");
        }
    }
}
