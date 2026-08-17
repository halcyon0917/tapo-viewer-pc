using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace TapoViewer.App.Controls;

/// <summary>
/// Hosts a sandboxed decoder's window inside the WPF visual tree.
/// </summary>
/// <remarks>
/// Two windows are involved. This control owns a plain container child window that WPF positions
/// and clips normally. The decoder — a separate, low-integrity process — creates its own top-level
/// window and reports the handle; we then reparent that handle into our container.
///
/// The direction is forced by UIPI: a low-integrity process cannot make itself a child of a
/// higher-integrity window, but a higher-integrity process may reparent and position a
/// lower-integrity one. So the sandboxed side creates and the privileged side adopts.
/// </remarks>
public sealed class VideoSurface : HwndHost
{
    private IntPtr _container;
    private IntPtr _decoderWindow;

    /// <summary>
    /// An attach requested before the container window existed.
    /// </summary>
    /// <remarks>
    /// <see cref="HwndHost"/> only builds its window once the control is actually realised, so a
    /// screen that is collapsed at startup has no container yet. Without remembering the request,
    /// the decoder handle arriving first would be dropped and that screen would show black until
    /// something else forced a re-attach.
    /// </remarks>
    private IntPtr _pendingWindow;

    private int _appliedWidth;
    private int _appliedHeight;

    /// <summary>Raised when the hosted surface is resized, in device pixels.</summary>
    public event EventHandler<(int Width, int Height)>? SurfaceResized;

    public VideoSurface()
    {
        // Self-healing sizing, rather than trying to guess the one right moment to measure.
        //
        // The decoder window must end up exactly the size of this control, but the attach can
        // arrive at any point relative to the layout pass — on first connect, on a quality switch
        // that destroys and recreates the decoder, on a grid change. Every single-shot attempt
        // (attach-time, or one deferred dispatch) loses one of those races: the surface goes
        // collapsed -> visible and arrange has not run, so there is no real size to apply and the
        // decoder keeps its 640x360 creation size, anchored top-left.
        //
        // LayoutUpdated fires after every arrange, so checking here catches all of them. It is
        // called often, hence the int comparison guard: SetWindowPos only happens when the size
        // actually changed.
        LayoutUpdated += (_, _) => Layout();
    }

    /// <summary>Adopts a decoder window reported by a <c>ready</c> event.</summary>
    public void AttachDecoderWindow(IntPtr decoderWindow)
    {
        if (decoderWindow == IntPtr.Zero)
        {
            return;
        }

        if (_container == IntPtr.Zero)
        {
            _pendingWindow = decoderWindow;
            return;
        }

        _pendingWindow = IntPtr.Zero;
        _decoderWindow = decoderWindow;

        // Force the next Layout() to push a size even if the control's dimensions are unchanged:
        // this is a brand-new decoder window still at its own creation size.
        _appliedWidth = 0;
        _appliedHeight = 0;

        // Convert the decoder's top-level popup into our child.
        var style = GetWindowLongPtr(decoderWindow, GwlStyle).ToInt64();
        style &= ~(long)WsPopup;
        style |= WsChild | WsVisible;
        SetWindowLongPtr(decoderWindow, GwlStyle, checked((IntPtr)style));

        SetParent(decoderWindow, _container);

        Layout();

        // Layout() above is usually a no-op, and that was the bug: an attach triggered by the
        // surface becoming visible runs BEFORE the layout pass, so ActualWidth is still 0 and
        // there is no real size to apply. The decoder window stayed one pixel wide and the pane
        // showed bare container until some unrelated change — clicking a layout button — forced
        // a resize. Re-applying at Loaded priority runs after the pass, when the size is known.
        Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Loaded, new Action(Layout));
    }

    public void DetachDecoderWindow() => _decoderWindow = IntPtr.Zero;

    protected override HandleRef BuildWindowCore(HandleRef hwndParent)
    {
        EnsureContainerClass();

        _container = CreateWindowEx(
            0,
            ContainerClassName,
            string.Empty,
            WsChild | WsVisible | WsClipChildren,
            0,
            0,
            1,
            1,
            hwndParent.Handle,
            IntPtr.Zero,
            IntPtr.Zero,
            IntPtr.Zero);

        if (_container == IntPtr.Zero)
        {
            throw new InvalidOperationException(
                $"Could not create the video container window ({Marshal.GetLastWin32Error()}).");
        }

        if (_pendingWindow != IntPtr.Zero)
        {
            var deferred = _pendingWindow;
            _pendingWindow = IntPtr.Zero;
            AttachDecoderWindow(deferred);
        }

        return new HandleRef(this, _container);
    }

    protected override void DestroyWindowCore(HandleRef hwnd)
    {
        // Release the decoder's window back to the desktop BEFORE destroying the container.
        // DestroyWindow takes the whole child chain with it, so skipping this would kill the
        // decoder's rendering window every time the surface is hidden — leaving a running,
        // sandboxed decoder with nowhere to draw and a permanently black pane on return.
        // Remembering it as pending means the next BuildWindowCore re-adopts it automatically.
        if (_decoderWindow != IntPtr.Zero)
        {
            SetParent(_decoderWindow, IntPtr.Zero);
            _pendingWindow = _decoderWindow;
            _decoderWindow = IntPtr.Zero;
        }

        if (_container != IntPtr.Zero)
        {
            DestroyWindow(_container);
            _container = IntPtr.Zero;
        }
    }

    protected override void OnRenderSizeChanged(SizeChangedInfo sizeInfo)
    {
        base.OnRenderSizeChanged(sizeInfo);
        Layout();
    }

    private void Layout()
    {
        var (width, height) = DeviceSize();

        // A degenerate size means we are being asked to lay out before measurement. Pushing it
        // would shrink the decoder's window to a pixel and leave it there; a later layout pass
        // will call back with a real size.
        if (width <= 1 || height <= 1)
        {
            return;
        }

        if (width == _appliedWidth && height == _appliedHeight && _decoderWindow != IntPtr.Zero)
        {
            return;
        }

        _appliedWidth = width;
        _appliedHeight = height;

        if (_decoderWindow != IntPtr.Zero)
        {
            SetWindowPos(_decoderWindow, IntPtr.Zero, 0, 0, width, height, SwpNoZOrder | SwpNoActivate);
        }

        SurfaceResized?.Invoke(this, (width, height));
    }

    /// <summary>Converts the control's DIP size to physical pixels for the child window.</summary>
    private (int Width, int Height) DeviceSize()
    {
        var width = ActualWidth;
        var height = ActualHeight;

        var source = PresentationSource.FromVisual(this);
        if (source?.CompositionTarget is not null)
        {
            var transform = source.CompositionTarget.TransformToDevice;
            width *= transform.M11;
            height *= transform.M22;
        }

        return (Math.Max((int)Math.Round(width), 1), Math.Max((int)Math.Round(height), 1));
    }

    private const string ContainerClassName = "TapoViewerVideoContainer";

    // Held in a static field so the GC cannot collect the delegate the window class points at.
    private static WndProcDelegate? _containerProc;
    private static bool _containerClassRegistered;

    /// <summary>
    /// Registers a container window class painted black.
    /// </summary>
    /// <remarks>
    /// The stock <c>static</c> class has no background brush, so any moment the container is
    /// visible without the decoder covering it — between attach and first frame, or during a
    /// quality switch while the old decoder is gone and the new one has not drawn — renders as
    /// white. On a dark video wall that reads as a fault. A black class brush makes those gaps
    /// invisible.
    /// </remarks>
    private static void EnsureContainerClass()
    {
        if (_containerClassRegistered)
        {
            return;
        }

        _containerProc = DefWindowProc;

        var windowClass = new WndClassEx
        {
            cbSize = Marshal.SizeOf<WndClassEx>(),
            lpfnWndProc = Marshal.GetFunctionPointerForDelegate(_containerProc),
            hInstance = GetModuleHandle(null),
            lpszClassName = ContainerClassName,
            hbrBackground = CreateSolidBrush(0x00000000),
        };

        if (RegisterClassEx(ref windowClass) == 0)
        {
            var error = Marshal.GetLastWin32Error();

            // 1410 = ERROR_CLASS_ALREADY_EXISTS, expected on a second surface.
            if (error != 1410)
            {
                throw new InvalidOperationException($"RegisterClassEx failed with {error}.");
            }
        }

        _containerClassRegistered = true;
    }

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

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ushort RegisterClassEx(ref WndClassEx windowClass);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr DefWindowProc(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr GetModuleHandle(string? moduleName);

    [DllImport("gdi32.dll")]
    private static extern IntPtr CreateSolidBrush(uint color);

    private const int GwlStyle = -16;
    private const long WsChild = 0x40000000;
    private const long WsVisible = 0x10000000;
    private const long WsPopup = 0x80000000;
    private const long WsClipChildren = 0x02000000;
    private const uint SwpNoZOrder = 0x0004;
    private const uint SwpNoActivate = 0x0010;

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateWindowEx(
        uint exStyle,
        string className,
        string windowName,
        long style,
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
    private static extern IntPtr SetParent(IntPtr child, IntPtr newParent);

    [DllImport("user32.dll", EntryPoint = "GetWindowLongPtrW", SetLastError = true)]
    private static extern IntPtr GetWindowLongPtr(IntPtr hwnd, int index);

    [DllImport("user32.dll", EntryPoint = "SetWindowLongPtrW", SetLastError = true)]
    private static extern IntPtr SetWindowLongPtr(IntPtr hwnd, int index, IntPtr value);

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
}
