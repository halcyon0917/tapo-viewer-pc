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

    /// <summary>Raised when the hosted surface is resized, in device pixels.</summary>
    public event EventHandler<(int Width, int Height)>? SurfaceResized;

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

        // Convert the decoder's top-level popup into our child.
        var style = GetWindowLongPtr(decoderWindow, GwlStyle).ToInt64();
        style &= ~(long)WsPopup;
        style |= WsChild | WsVisible;
        SetWindowLongPtr(decoderWindow, GwlStyle, checked((IntPtr)style));

        SetParent(decoderWindow, _container);

        Layout();
    }

    public void DetachDecoderWindow() => _decoderWindow = IntPtr.Zero;

    protected override HandleRef BuildWindowCore(HandleRef hwndParent)
    {
        _container = CreateWindowEx(
            0,
            "static",
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
