using System.Runtime.InteropServices;
using LibVLCSharp.Shared;
using TapoViewer.Core.Decoding;
using TapoViewer.Core.Rtsp;
using TapoViewer.Core.Security;

namespace TapoViewer.Decoder;

/// <summary>
/// The decoder host: one bare Win32 window, one libVLC player, driven over stdin.
/// </summary>
/// <remarks>
/// The window is created as a hidden top-level popup and its handle is reported to the parent,
/// which then reparents it into the video grid. It has to be this way round: UIPI forbids a
/// low-integrity process from parenting itself to a higher-integrity window, but a
/// higher-integrity parent may freely reparent and position a low-integrity child's window.
/// </remarks>
internal sealed class DecoderHost : IDisposable
{
    private const string WindowClassName = "TapoViewerDecoderSurface";

    private readonly TextWriter _events;
    private readonly object _gate = new();

    private LibVLC? _libvlc;
    private MediaPlayer? _player;
    private Media? _media;
    private IntPtr _hwnd;
    private WndProcDelegate? _wndProc;

    internal DecoderHost(TextWriter events)
    {
        _events = events;
    }

    internal int Run(string[] args)
    {
        CreateSurface();

        Emit(new DecoderEvent { Event = DecoderEvent.EventReady, Hwnd = _hwnd.ToInt64() });

        var reader = new Thread(ReadCommands)
        {
            IsBackground = true,
            Name = "decoder-stdin",
        };

        reader.Start();

        PumpMessages();
        return 0;
    }

    // --- command loop ---------------------------------------------------------------------

    private void ReadCommands()
    {
        try
        {
            string? line;
            while ((line = Console.In.ReadLine()) is not null)
            {
                var command = DecoderProtocol.ParseCommand(line);
                if (command is null)
                {
                    Emit(new DecoderEvent
                    {
                        Event = DecoderEvent.EventError,
                        Message = "Malformed or oversized command ignored.",
                    });

                    continue;
                }

                if (!Dispatch(command))
                {
                    break;
                }
            }
        }
        catch (IOException)
        {
            // Parent went away; fall through and quit.
        }

        PostQuitMessage(0);
    }

    /// <summary>Returns false when the host should shut down.</summary>
    private bool Dispatch(DecoderCommand command)
    {
        try
        {
            switch (command.Op)
            {
                case DecoderCommand.OpPlay:
                    Play(command);
                    return true;

                case DecoderCommand.OpStop:
                    Stop();
                    return true;

                case DecoderCommand.OpResize:
                    SetWindowPos(
                        _hwnd,
                        IntPtr.Zero,
                        command.X,
                        command.Y,
                        command.Width,
                        command.Height,
                        SwpNoZOrder | SwpNoActivate);
                    return true;

                case DecoderCommand.OpQuit:
                    Stop();
                    return false;

                default:
                    Emit(new DecoderEvent
                    {
                        Event = DecoderEvent.EventError,
                        Message = $"Unknown op '{command.Op}'.",
                    });

                    return true;
            }
        }
        catch (Exception ex) when (ex is UntrustedHostException or ArgumentException or InvalidOperationException)
        {
            Emit(new DecoderEvent { Event = DecoderEvent.EventError, Message = ex.Message });
            return true;
        }
        catch (Exception ex)
        {
            // Anything else — a missing native dependency, a libVLC initialisation failure — must
            // still reach the UI. Letting it escape kills this thread silently, and the parent
            // then waits forever for a stream that will never arrive, with nothing on screen to
            // explain why. A deliberately broad catch is the right call at a process boundary.
            Emit(new DecoderEvent
            {
                Event = DecoderEvent.EventError,
                Message = $"{ex.GetType().Name}: {ex.Message}",
            });

            return true;
        }
    }

    private void Play(DecoderCommand command)
    {
        if (string.IsNullOrWhiteSpace(command.Host))
        {
            throw new ArgumentException("Play command carried no host.");
        }

        // The address is re-validated here even though the parent already checked it. This
        // process is the one that opens the socket, so it enforces its own policy rather than
        // trusting a caller.
        var endpoint = HostGuard.Pin(command.Host, command.Port);
        var quality = string.Equals(command.Path, "/stream2", StringComparison.OrdinalIgnoreCase)
            ? StreamQuality.Standard
            : StreamQuality.High;

        var target = new RtspTarget(endpoint, quality);

        lock (_gate)
        {
            StopLocked();

            LibVLCSharp.Shared.Core.Initialize();

            _libvlc = new LibVLC(
                "--intf=dummy",
                "--no-plugins-cache",
                "--no-osd",
                "--no-snapshot-preview",
                "--quiet");

            var user = command.User ?? string.Empty;
            var pass = command.Pass ?? string.Empty;

            // Credentials go through libVLC's login callback so they never enter the URI, and
            // therefore never reach libVLC's logs or any dump of the media location.
            _libvlc.SetDialogHandlers(
                error: (_, _) => Task.CompletedTask,
                login: (dialog, _, _, defaultUsername, _, _) =>
                {
                    dialog?.PostLogin(string.IsNullOrEmpty(user) ? defaultUsername : user, pass, store: false);
                    return Task.CompletedTask;
                },
                question: (dialog, _, _, _, _, _, _, _) =>
                {
                    dialog?.Dismiss();
                    return Task.CompletedTask;
                },
                displayProgress: (_, _, _, _, _, _, _) => Task.CompletedTask,
                updateProgress: (_, _, _) => Task.CompletedTask);

            _media = new Media(_libvlc, target.ToUri());
            _media.AddOption(":rtsp-tcp");
            _media.AddOption(":network-caching=300");

            _player = new MediaPlayer(_libvlc)
            {
                Hwnd = _hwnd,
                EnableMouseInput = false,
                EnableKeyInput = false,
            };

            _player.Playing += (_, _) => EmitState("Playing");
            _player.Stopped += (_, _) => EmitState("Stopped");
            _player.EncounteredError += (_, _) => Emit(new DecoderEvent
            {
                Event = DecoderEvent.EventError,
                Message = "libVLC could not play the stream. Check the camera account credentials.",
            });

            if (!_player.Play(_media))
            {
                Emit(new DecoderEvent
                {
                    Event = DecoderEvent.EventError,
                    Message = "libVLC refused to start playback.",
                });
            }
        }
    }

    private void Stop()
    {
        lock (_gate)
        {
            StopLocked();
        }
    }

    private void StopLocked()
    {
        if (_player is not null)
        {
            _player.Stop();
            _player.Dispose();
            _player = null;
        }

        _media?.Dispose();
        _media = null;

        _libvlc?.Dispose();
        _libvlc = null;
    }

    private void EmitState(string state)
        => Emit(new DecoderEvent { Event = DecoderEvent.EventState, Value = state });

    private void Emit(DecoderEvent value)
    {
        lock (_events)
        {
            _events.WriteLine(DecoderProtocol.Serialize(value));
            _events.Flush();
        }
    }

    // --- window ---------------------------------------------------------------------------

    private void CreateSurface()
    {
        _wndProc = WindowProc;

        var moduleHandle = GetModuleHandle(null);

        var windowClass = new WndClassEx
        {
            cbSize = Marshal.SizeOf<WndClassEx>(),
            lpfnWndProc = Marshal.GetFunctionPointerForDelegate(_wndProc),
            hInstance = moduleHandle,
            lpszClassName = WindowClassName,
            hbrBackground = CreateSolidBrush(0x00000000),
        };

        if (RegisterClassEx(ref windowClass) == 0)
        {
            var error = Marshal.GetLastWin32Error();

            // 1410 = ERROR_CLASS_ALREADY_EXISTS, harmless on a re-entrant launch.
            if (error != 1410)
            {
                throw new InvalidOperationException($"RegisterClassEx failed with {error}.");
            }
        }

        _hwnd = CreateWindowEx(
            0,
            WindowClassName,
            "TapoViewer decoder surface",
            WsPopup | WsClipChildren,
            0,
            0,
            640,
            360,
            IntPtr.Zero,
            IntPtr.Zero,
            moduleHandle,
            IntPtr.Zero);

        if (_hwnd == IntPtr.Zero)
        {
            throw new InvalidOperationException(
                $"CreateWindowEx failed with {Marshal.GetLastWin32Error()}.");
        }
    }

    private static void PumpMessages()
    {
        while (GetMessage(out var message, IntPtr.Zero, 0, 0) > 0)
        {
            TranslateMessage(ref message);
            DispatchMessage(ref message);
        }
    }

    private IntPtr WindowProc(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam)
    {
        if (msg == WmDestroy)
        {
            PostQuitMessage(0);
            return IntPtr.Zero;
        }

        return DefWindowProc(hwnd, msg, wParam, lParam);
    }

    public void Dispose()
    {
        Stop();

        if (_hwnd != IntPtr.Zero)
        {
            DestroyWindow(_hwnd);
            _hwnd = IntPtr.Zero;
        }
    }

    private const uint WmDestroy = 0x0002;
    private const uint WsPopup = 0x80000000;
    private const uint WsClipChildren = 0x02000000;
    private const uint SwpNoZOrder = 0x0004;
    private const uint SwpNoActivate = 0x0010;

    private delegate IntPtr WndProcDelegate(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WndClassEx
    {
        public int cbSize;
        public uint style;
        public IntPtr lpfnWndProc;
        public int cbClsExtra;
        public int cbWndExtra;
        public IntPtr hInstance;
        public IntPtr hIcon;
        public IntPtr hCursor;
        public IntPtr hbrBackground;
        [MarshalAs(UnmanagedType.LPWStr)] public string? lpszMenuName;
        [MarshalAs(UnmanagedType.LPWStr)] public string? lpszClassName;
        public IntPtr hIconSm;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Msg
    {
        public IntPtr hwnd;
        public uint message;
        public IntPtr wParam;
        public IntPtr lParam;
        public uint time;
        public int ptX;
        public int ptY;
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ushort RegisterClassEx(ref WndClassEx windowClass);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateWindowEx(
        uint exStyle,
        string className,
        string windowName,
        uint style,
        int x,
        int y,
        int width,
        int height,
        IntPtr parent,
        IntPtr menu,
        IntPtr instance,
        IntPtr param);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyWindow(IntPtr hwnd);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWindowPos(
        IntPtr hwnd,
        IntPtr insertAfter,
        int x,
        int y,
        int cx,
        int cy,
        uint flags);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr DefWindowProc(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetMessage(out Msg message, IntPtr hwnd, uint filterMin, uint filterMax);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TranslateMessage(ref Msg message);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr DispatchMessage(ref Msg message);

    [DllImport("user32.dll")]
    private static extern void PostQuitMessage(int exitCode);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr GetModuleHandle(string? moduleName);

    [DllImport("gdi32.dll")]
    private static extern IntPtr CreateSolidBrush(uint color);
}
