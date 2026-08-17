using System.Collections.ObjectModel;
using System.Windows.Threading;
using TapoViewer.App.Services;
using TapoViewer.Core.Configuration;
using TapoViewer.Core.Onvif;
using TapoViewer.Core.Rtsp;
using TapoViewer.Core.Security;

namespace TapoViewer.App.ViewModels;

/// <summary>One camera in the grid.</summary>
public sealed class CameraTileViewModel : ObservableObject, IDisposable
{
    private static readonly TimeSpan MotionHold = TimeSpan.FromSeconds(8);

    private readonly Dispatcher _dispatcher;
    private readonly DispatcherTimer _motionTimer;

    private string _status = "Idle";
    private bool _isMotionActive;
    private bool _isConnected;
    private bool _isLive;
    private bool _isConnecting;
    private string? _error;
    private OnvifPreset? _selectedPreset;
    private StreamQuality _quality = StreamQuality.High;

    public CameraTileViewModel(
        CameraSession session,
        Dispatcher dispatcher,
        Func<CameraTileViewModel, Task>? onEdit = null,
        Action<CameraTileViewModel>? onRemove = null)
    {
        Session = session;
        _dispatcher = dispatcher;

        // Async so a failed save surfaces as a tile error instead of being swallowed by a
        // discarded task.
        EditCommand = new AsyncRelayCommand(
            _ => onEdit is null ? Task.CompletedTask : onEdit(this),
            _ => onEdit is not null,
            ex => Error = Explain(ex));

        RemoveCommand = new RelayCommand(_ => onRemove?.Invoke(this), _ => onRemove is not null);

        _motionTimer = new DispatcherTimer(DispatcherPriority.Normal, dispatcher)
        {
            Interval = MotionHold,
        };

        _motionTimer.Tick += (_, _) =>
        {
            _motionTimer.Stop();
            IsMotionActive = false;
        };

        session.StatusChanged += (_, status) => OnDispatcher(() => Status = status);
        session.Failed += (_, message) => OnDispatcher(() => Error = message);
        session.MotionDetected += (_, _) => OnDispatcher(FlagMotion);
        session.PlayingChanged += (_, playing) => OnDispatcher(() =>
        {
            IsLive = playing;
            if (playing)
            {
                IsConnecting = false;
            }

            Raise(nameof(StateHeadline));
        });
        session.SurfaceReady += (_, handle) => OnDispatcher(() =>
        {
            CurrentSurface = handle;
            SurfaceReady?.Invoke(this, handle);
        });

        ConnectCommand = new AsyncRelayCommand(_ => ConnectAsync(), onError: ex => Error = Explain(ex));
        ReconnectCommand = new AsyncRelayCommand(_ => ConnectAsync(), onError: ex => Error = Explain(ex));
        ToggleQualityCommand = new AsyncRelayCommand(_ => ToggleQualityAsync(), onError: ex => Error = Explain(ex));

        MoveCommand = new AsyncRelayCommand(
            parameter => MoveAsync(parameter as string ?? string.Empty),
            _ => SupportsPtz,
            ex => Error = Explain(ex));

        StopMoveCommand = new AsyncRelayCommand(
            _ => Session.StopMoveAsync(),
            _ => SupportsPtz,
            ex => Error = Explain(ex));

        GotoPresetCommand = new AsyncRelayCommand(
            _ => GotoSelectedPresetAsync(),
            _ => SupportsPtz && SelectedPreset is not null,
            ex => Error = Explain(ex));

    }

    /// <summary>Raised when the decoder surface is ready to be adopted by the view.</summary>
    public event EventHandler<IntPtr>? SurfaceReady;

    public CameraSession Session { get; }

    /// <summary>
    /// The decoder's window handle once it exists, or <see cref="IntPtr.Zero"/>.
    /// </summary>
    /// <remarks>
    /// <see cref="SurfaceReady"/> fires once, but the same decoder window has to be re-adopted
    /// every time the user navigates between the grid and the live screen — a host control
    /// created after the event would otherwise show nothing. Views read this on load and attach
    /// if it is already set.
    /// </remarks>
    public IntPtr CurrentSurface { get; private set; }

    /// <summary>
    /// True only while the decoder is actually rendering.
    /// </summary>
    /// <remarks>
    /// Drives the video surface's visibility. It has to be exact, because of WPF airspace: the
    /// decoder's child window paints over everything WPF draws in that rectangle, so a "no
    /// signal" or error panel placed behind it would be invisible. The surface is therefore
    /// hidden outright whenever there is nothing to show, and the state panel takes its place.
    /// </remarks>
    public bool IsLive
    {
        get => _isLive;
        private set
        {
            if (Set(ref _isLive, value))
            {
                Raise(nameof(ShowStatePanel));
            }
        }
    }

    public bool ShowStatePanel => !IsLive;

    public bool IsConnecting
    {
        get => _isConnecting;
        private set => Set(ref _isConnecting, value);
    }

    /// <summary>Headline for the state panel when video is not showing.</summary>
    public string StateHeadline => HasError ? "Connection failed" : IsConnecting ? "Connecting…" : "Not connected";

    public CameraProfile Profile => Session.Profile;

    public string DisplayName => Profile.DisplayName;

    public string Address => $"{Profile.Host}:{Profile.RtspPort}";

    public ObservableCollection<OnvifPreset> Presets { get; } = [];

    public AsyncRelayCommand ConnectCommand { get; }

    public AsyncRelayCommand ReconnectCommand { get; }

    public AsyncRelayCommand ToggleQualityCommand { get; }

    public AsyncRelayCommand MoveCommand { get; }

    public AsyncRelayCommand StopMoveCommand { get; }

    public AsyncRelayCommand GotoPresetCommand { get; }

    public AsyncRelayCommand EditCommand { get; }

    public RelayCommand RemoveCommand { get; }

    public string Status
    {
        get => _status;
        private set => Set(ref _status, value);
    }

    public string? Error
    {
        get => _error;
        private set
        {
            if (Set(ref _error, value))
            {
                Raise(nameof(HasError));
                Raise(nameof(StateHeadline));
            }
        }
    }

    public bool HasError => !string.IsNullOrEmpty(Error);

    public bool IsConnected
    {
        get => _isConnected;
        private set => Set(ref _isConnected, value);
    }

    public bool IsMotionActive
    {
        get => _isMotionActive;
        private set => Set(ref _isMotionActive, value);
    }

    public bool SupportsPtz => Session.SupportsPtz;

    public StreamQuality Quality
    {
        get => _quality;
        private set
        {
            if (Set(ref _quality, value))
            {
                Raise(nameof(QualityLabel));
            }
        }
    }

    public string QualityLabel => Quality == StreamQuality.High ? "HD" : "SD";

    /// <summary>Shown in the tile so the sandbox state is visible, not just documented.</summary>
    public string DecoderIntegrity => Session.DecoderIntegrity;

    public OnvifPreset? SelectedPreset
    {
        get => _selectedPreset;
        set
        {
            if (Set(ref _selectedPreset, value))
            {
                GotoPresetCommand.RaiseCanExecuteChanged();
            }
        }
    }

    public async Task ConnectAsync()
    {
        Error = null;
        IsConnecting = true;
        Raise(nameof(StateHeadline));

        try
        {
            await ConnectCoreAsync().ConfigureAwait(true);
        }
        finally
        {
            IsConnecting = false;
            Raise(nameof(StateHeadline));
        }
    }

    private async Task ConnectCoreAsync()
    {
        await Session.ConnectControlPlaneAsync().ConfigureAwait(true);

        Presets.Clear();
        foreach (var preset in Session.Presets)
        {
            Presets.Add(preset);
        }

        Raise(nameof(SupportsPtz));
        MoveCommand.RaiseCanExecuteChanged();
        StopMoveCommand.RaiseCanExecuteChanged();
        GotoPresetCommand.RaiseCanExecuteChanged();

        await Session.StartVideoAsync(Profile.PreferredQuality).ConfigureAwait(true);
        Quality = Profile.PreferredQuality;

        Session.StartMotionEvents();

        IsConnected = true;
        Raise(nameof(DecoderIntegrity));
    }

    private async Task ToggleQualityAsync()
    {
        var next = Quality == StreamQuality.High ? StreamQuality.Standard : StreamQuality.High;
        await Session.SetQualityAsync(next).ConfigureAwait(true);
        Quality = next;
        Raise(nameof(DecoderIntegrity));
    }

    private Task MoveAsync(string direction) => direction switch
    {
        "left" => Session.MoveAsync(-0.6, 0, 0),
        "right" => Session.MoveAsync(0.6, 0, 0),
        "up" => Session.MoveAsync(0, 0.6, 0),
        "down" => Session.MoveAsync(0, -0.6, 0),
        "in" => Session.MoveAsync(0, 0, 0.6),
        "out" => Session.MoveAsync(0, 0, -0.6),
        _ => Task.CompletedTask,
    };

    private Task GotoSelectedPresetAsync()
        => SelectedPreset is null ? Task.CompletedTask : Session.GotoPresetAsync(SelectedPreset.Token);

    public void ResizeSurface(int width, int height) => Session.ResizeSurface(width, height);

    private void FlagMotion()
    {
        IsMotionActive = true;
        _motionTimer.Stop();
        _motionTimer.Start();
    }

    private void OnDispatcher(Action action)
    {
        if (_dispatcher.CheckAccess())
        {
            action();
        }
        else
        {
            _dispatcher.BeginInvoke(action);
        }
    }

    /// <summary>Turns an exception into something a person can act on.</summary>
    private static string Explain(Exception ex) => ex switch
    {
        OnvifAuthenticationException => "Camera rejected the account. Check the Camera Account in the Tapo app.",
        UntrustedHostException host => host.Message,
        OnvifException onvif => onvif.Message,
        TimeoutException => "The decoder did not start in time.",
        _ => $"{ex.GetType().Name}: {ex.Message}",
    };

    public void Dispose()
    {
        _motionTimer.Stop();
        Session.Dispose();
    }
}
