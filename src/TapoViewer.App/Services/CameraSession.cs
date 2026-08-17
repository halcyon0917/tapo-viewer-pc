using TapoViewer.Core.Configuration;
using TapoViewer.Core.Decoding;
using TapoViewer.Core.Onvif;
using TapoViewer.Core.Rtsp;
using TapoViewer.Core.Sandbox;
using TapoViewer.Core.Security;

namespace TapoViewer.App.Services;

/// <summary>Everything one camera needs: control plane, video plane, and credentials.</summary>
/// <remarks>
/// The ONVIF client has to hold the password for the session's lifetime — every request carries a
/// freshly digested copy of it — so the <see cref="Secret"/> lives as long as this object and is
/// zeroed on disposal. The video plane, by contrast, receives the password exactly once when
/// playback starts and never holds it again.
/// </remarks>
public sealed class CameraSession : IDisposable
{
    private static readonly TimeSpan SubscriptionTerm = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan PullTimeout = TimeSpan.FromSeconds(20);

    private readonly ICredentialVault _vault;
    private readonly SandboxIntegrity _integrity;
    private readonly SemaphoreSlim _decoderGate = new(1, 1);

    private CameraCredential? _credential;
    private OnvifClient? _onvif;
    private OnvifCapabilities? _capabilities;
    private string? _profileToken;
    private PinnedEndpoint? _onvifEndpoint;

    private DecoderConnection? _decoder;
    private CancellationTokenSource? _eventLoop;
    private bool _disposed;

    public CameraSession(
        CameraProfile profile,
        ICredentialVault vault,
        SandboxIntegrity integrity = SandboxIntegrity.Low)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(vault);

        Profile = profile;
        _vault = vault;
        _integrity = integrity;
    }

    public CameraProfile Profile { get; private set; }

    public StreamQuality Quality { get; private set; }

    public bool SupportsPtz => _capabilities?.SupportsPtz == true;

    public bool SupportsEvents => _capabilities?.SupportsEvents == true;

    public IReadOnlyList<OnvifPreset> Presets { get; private set; } = [];

    /// <summary>Sandbox integrity of the running decoder, for display in the UI.</summary>
    public string DecoderIntegrity => _decoder is null
        ? "not running"
        : SandboxInspector.Describe(SandboxInspector.GetIntegritySid(_decoder.ProcessId));

    public event EventHandler<string>? StatusChanged;

    public event EventHandler<IntPtr>? SurfaceReady;

    public event EventHandler? MotionDetected;

    public event EventHandler<string>? Failed;

    /// <summary>
    /// Raised with true once the decoder is rendering, false whenever it stops.
    /// </summary>
    /// <remarks>
    /// An explicit signal rather than making the UI match on the human-readable status string,
    /// which is for display and free to change wording.
    /// </remarks>
    public event EventHandler<bool>? PlayingChanged;

    /// <summary>Connects the control plane: authenticates, discovers services and presets.</summary>
    public async Task ConnectControlPlaneAsync(CancellationToken cancellationToken = default)
    {
        Report("Connecting…");

        // This method is re-entrant by design — "Retry" and "Reconnect all" both call it on an
        // existing session — so the previous credential and ONVIF client must be released before
        // they are replaced.
        //
        // Leaking the credential here is not merely untidy. Secret pins its buffer with a
        // GCHandle, which is a strong root: an abandoned Secret is never collected AND never
        // zeroed, so every reconnect would strand another plaintext copy of the camera-account
        // password at a fixed address in this privileged process for its whole lifetime —
        // recoverable from a crash dump or the page file, and the exact opposite of what Secret
        // exists to guarantee.
        //
        // The event loop is cancelled first because it holds the OnvifClient we are about to
        // dispose.
        _eventLoop?.Cancel();
        _eventLoop?.Dispose();
        _eventLoop = null;

        _onvif?.Dispose();
        _onvif = null;

        _credential?.Dispose();
        _credential = null;

        _credential = _vault.Retrieve(Profile.Id)
            ?? throw new InvalidOperationException(
                $"No stored credential for '{Profile.DisplayName}'. Re-enter its camera account.");

        _onvifEndpoint = await HostGuard
            .PinAsync(Profile.Host, Profile.OnvifPort, cancellationToken)
            .ConfigureAwait(false);

        _onvif = new OnvifClient(_onvifEndpoint, _credential.UserName, _credential.Password);

        _capabilities = await _onvif.GetCapabilitiesAsync(cancellationToken).ConfigureAwait(false);

        if (_capabilities.Media is null)
        {
            throw new OnvifException("The camera advertises no media service.");
        }

        var profiles = await _onvif.GetProfilesAsync(_capabilities.Media, cancellationToken)
            .ConfigureAwait(false);

        _profileToken = profiles[0].Token;

        if (_capabilities.SupportsPtz)
        {
            try
            {
                Presets = await _onvif
                    .GetPresetsAsync(_capabilities.Ptz!, _profileToken, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OnvifException)
            {
                Presets = [];
            }
        }

        Report("Connected");
    }

    /// <summary>Starts the sandboxed decoder and begins playback.</summary>
    public async Task StartVideoAsync(StreamQuality quality, CancellationToken cancellationToken = default)
    {
        await _decoderGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            StopVideoCore();

            if (_credential is null)
            {
                throw new InvalidOperationException("Connect the control plane before starting video.");
            }

            Quality = quality;
            Report("Starting decoder…");

            var connection = DecoderConnection.Start(integrity: _integrity);
            _decoder = connection;

            connection.EventReceived += OnDecoderEvent;
            connection.DiagnosticReceived += (_, line) =>
            {
                DiagnosticLog.Write($"decoder[{Profile.DisplayName}] stderr: {line}");
                Report($"decoder: {line}");
            };

            DiagnosticLog.Write(
                $"decoder[{Profile.DisplayName}] pid {connection.ProcessId} at {connection.Integrity} integrity");

            var surface = await connection
                .WaitForSurfaceAsync(TimeSpan.FromSeconds(10), cancellationToken)
                .ConfigureAwait(false);

            SurfaceReady?.Invoke(this, surface);

            var endpoint = await HostGuard
                .PinAsync(Profile.Host, Profile.RtspPort, cancellationToken)
                .ConfigureAwait(false);

            connection.Play(endpoint, quality, _credential.UserName, _credential.Password.Reveal());
            Report("Buffering…");
        }
        finally
        {
            _decoderGate.Release();
        }
    }

    public async Task SetQualityAsync(StreamQuality quality, CancellationToken cancellationToken = default)
    {
        if (quality == Quality && _decoder is not null)
        {
            return;
        }

        await StartVideoAsync(quality, cancellationToken).ConfigureAwait(false);
    }

    public void ResizeSurface(int width, int height) => _decoder?.Resize(0, 0, width, height);

    // --- PTZ -------------------------------------------------------------------------------

    public async Task MoveAsync(double pan, double tilt, double zoom, CancellationToken cancellationToken = default)
    {
        if (_onvif is null || _capabilities?.Ptz is null || _profileToken is null)
        {
            return;
        }

        await _onvif.ContinuousMoveAsync(
            _capabilities.Ptz,
            _profileToken,
            PtzVelocity.Clamped(pan, tilt, zoom),
            cancellationToken).ConfigureAwait(false);
    }

    public async Task StopMoveAsync(CancellationToken cancellationToken = default)
    {
        if (_onvif is null || _capabilities?.Ptz is null || _profileToken is null)
        {
            return;
        }

        await _onvif.StopAsync(_capabilities.Ptz, _profileToken, cancellationToken).ConfigureAwait(false);
    }

    public async Task GotoPresetAsync(string presetToken, CancellationToken cancellationToken = default)
    {
        if (_onvif is null || _capabilities?.Ptz is null || _profileToken is null)
        {
            return;
        }

        await _onvif.GotoPresetAsync(_capabilities.Ptz, _profileToken, presetToken, cancellationToken)
            .ConfigureAwait(false);
    }

    // --- motion events ---------------------------------------------------------------------

    /// <summary>Starts the pull-point loop. Safe to call when the camera has no event service.</summary>
    public void StartMotionEvents()
    {
        if (_onvif is null || _capabilities?.Events is null || !Profile.MotionEventsEnabled)
        {
            return;
        }

        _eventLoop?.Cancel();
        _eventLoop = new CancellationTokenSource();

        _ = PollMotionAsync(_onvif, _capabilities.Events, _eventLoop.Token);
    }

    private async Task PollMotionAsync(OnvifClient client, Uri eventService, CancellationToken cancellationToken)
    {
        var backoff = TimeSpan.FromSeconds(2);

        while (!cancellationToken.IsCancellationRequested)
        {
            OnvifSubscription? subscription = null;

            try
            {
                subscription = await client
                    .CreatePullPointSubscriptionAsync(eventService, SubscriptionTerm, cancellationToken)
                    .ConfigureAwait(false);

                backoff = TimeSpan.FromSeconds(2);

                while (!cancellationToken.IsCancellationRequested)
                {
                    var events = await client
                        .PullMessagesAsync(subscription, PullTimeout, cancellationToken: cancellationToken)
                        .ConfigureAwait(false);

                    if (events.Any(e => e.IsMotionDetected))
                    {
                        MotionDetected?.Invoke(this, EventArgs.Empty);
                    }

                    if (DateTimeOffset.UtcNow > subscription.ExpiresUtc - TimeSpan.FromSeconds(30))
                    {
                        await client.RenewAsync(subscription, SubscriptionTerm, cancellationToken)
                            .ConfigureAwait(false);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex) when (ex is OnvifException or OnvifAuthenticationException or UntrustedHostException)
            {
                Report($"Motion events interrupted: {ex.Message}");

                try
                {
                    await Task.Delay(backoff, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                // Cap the backoff so a camera that is merely rebooting is picked up promptly,
                // but a permanently broken event service does not spin.
                backoff = TimeSpan.FromSeconds(Math.Min(backoff.TotalSeconds * 2, 60));
            }
            finally
            {
                if (subscription is not null)
                {
                    try
                    {
                        await client.UnsubscribeAsync(subscription, CancellationToken.None).ConfigureAwait(false);
                    }
                    catch (OnvifException)
                    {
                        // Subscription may already be gone.
                    }
                    catch (OnvifAuthenticationException)
                    {
                        // Ditto.
                    }
                }
            }
        }
    }

    private void OnDecoderEvent(object? sender, DecoderEvent value)
    {
        switch (value.Event)
        {
            case DecoderEvent.EventState:
                Report(value.Value ?? "?");
                PlayingChanged?.Invoke(this, string.Equals(value.Value, "Playing", StringComparison.Ordinal));
                break;

            case DecoderEvent.EventError:
                PlayingChanged?.Invoke(this, false);
                Failed?.Invoke(this, value.Message ?? "Decoder error");
                break;
        }
    }

    public void StopVideo()
    {
        _decoderGate.Wait();
        try
        {
            StopVideoCore();
        }
        finally
        {
            _decoderGate.Release();
        }
    }

    private void StopVideoCore()
    {
        if (_decoder is null)
        {
            return;
        }

        PlayingChanged?.Invoke(this, false);

        _decoder.EventReceived -= OnDecoderEvent;
        _decoder.Dispose();
        _decoder = null;
    }

    private void Report(string status)
    {
        DiagnosticLog.Write($"[{Profile.DisplayName}] {status}");
        StatusChanged?.Invoke(this, status);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        _eventLoop?.Cancel();
        _eventLoop?.Dispose();

        StopVideoCore();

        _onvif?.Dispose();
        _credential?.Dispose();
        _decoderGate.Dispose();
    }
}
