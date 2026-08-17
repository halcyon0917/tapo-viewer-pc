using System.Windows;
using System.Windows.Controls;
using TapoViewer.App.ViewModels;

namespace TapoViewer.App.Controls;

/// <summary>
/// One camera in the grid: hosted video plus its overlay controls.
/// </summary>
/// <remarks>
/// The decoder-window handoff cannot be expressed as a binding — adopting a foreign HWND is an
/// imperative act — so this code-behind bridges the view model's <c>SurfaceReady</c> event to
/// <see cref="VideoSurface.AttachDecoderWindow"/>, and pushes size changes back down so libVLC
/// renders at the right pixel dimensions rather than being stretched by the window manager.
/// </remarks>
public partial class CameraTile : UserControl
{
    private CameraTileViewModel? _viewModel;

    public CameraTile()
    {
        InitializeComponent();

        DataContextChanged += OnDataContextChanged;
        IsVisibleChanged += OnIsVisibleChanged;
        Surface.SurfaceResized += OnSurfaceResized;
        Unloaded += OnUnloaded;
    }

    private void OnIsVisibleChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        // The live screen may have taken this decoder's window; take it back when the wall
        // becomes visible again.
        if (IsVisible)
        {
            AttachExistingSurface();
        }
    }

    private void AttachExistingSurface()
    {
        if (_viewModel is { CurrentSurface: var handle } && handle != IntPtr.Zero)
        {
            Surface.AttachDecoderWindow(handle);
        }
    }

    private void OnDataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        if (_viewModel is not null)
        {
            _viewModel.SurfaceReady -= OnSurfaceReady;
        }

        _viewModel = e.NewValue as CameraTileViewModel;

        if (_viewModel is null)
        {
            return;
        }

        _viewModel.SurfaceReady += OnSurfaceReady;

        // A decoder may already be running when this tile is re-created by a layout change.
        AttachExistingSurface();
    }

    private void OnSurfaceReady(object? sender, IntPtr handle) => Surface.AttachDecoderWindow(handle);

    private void OnSurfaceResized(object? sender, (int Width, int Height) size)
        => _viewModel?.ResizeSurface(size.Width, size.Height);

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        if (_viewModel is not null)
        {
            _viewModel.SurfaceReady -= OnSurfaceReady;
        }

        Surface.DetachDecoderWindow();
    }
}
