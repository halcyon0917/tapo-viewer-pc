using System.Collections.ObjectModel;
using System.Windows.Threading;
using TapoViewer.App.Dialogs;
using TapoViewer.App.Services;
using TapoViewer.Core.Configuration;
using TapoViewer.Core.Security;

namespace TapoViewer.App.ViewModels;

public sealed class MainViewModel : ObservableObject, IDisposable
{
    private readonly CameraConfigStore _store;
    private readonly ICredentialVault _vault;
    private readonly Dispatcher _dispatcher;

    private int _gridColumns = 2;
    private string? _banner;

    public MainViewModel(CameraConfigStore store, ICredentialVault vault, Dispatcher dispatcher)
    {
        _store = store;
        _vault = vault;
        _dispatcher = dispatcher;

        SetLayoutCommand = new RelayCommand(parameter =>
        {
            if (parameter is string text && int.TryParse(text, out var columns))
            {
                GridColumns = columns;
            }
        });

        ConnectAllCommand = new AsyncRelayCommand(_ => ConnectAllAsync(), onError: ex => Banner = ex.Message);
        ReloadCommand = new AsyncRelayCommand(_ => ReloadAsync(), onError: ex => Banner = ex.Message);
        AddCameraCommand = new AsyncRelayCommand(_ => AddCameraAsync(), onError: ex => Banner = ex.Message);
    }

    /// <summary>
    /// Shows the camera editor and returns its result, or <see langword="null"/> if cancelled.
    /// </summary>
    /// <remarks>
    /// Supplied by the view. Keeps window ownership out of the view model without pulling in a
    /// dialog-service abstraction that would be larger than the problem.
    /// </remarks>
    public Func<CameraProfile?, CameraEditorResult?>? RequestEditor { get; set; }

    /// <summary>Asks the user to confirm a destructive action. Supplied by the view.</summary>
    public Func<string, bool>? RequestConfirmation { get; set; }

    public AsyncRelayCommand AddCameraCommand { get; }

    public ObservableCollection<CameraTileViewModel> Cameras { get; } = [];

    public RelayCommand SetLayoutCommand { get; }

    public AsyncRelayCommand ConnectAllCommand { get; }

    public AsyncRelayCommand ReloadCommand { get; }

    public int GridColumns
    {
        get => _gridColumns;
        set => Set(ref _gridColumns, value);
    }

    /// <summary>Non-fatal message shown across the top of the window.</summary>
    public string? Banner
    {
        get => _banner;
        set
        {
            if (Set(ref _banner, value))
            {
                Raise(nameof(HasBanner));
            }
        }
    }

    public bool HasBanner => !string.IsNullOrEmpty(Banner);

    public bool IsEmpty => Cameras.Count == 0;

    public string ConfigPath => _store.FilePath;

    public async Task ReloadAsync()
    {
        foreach (var camera in Cameras)
        {
            camera.Dispose();
        }

        Cameras.Clear();

        IReadOnlyList<CameraProfile> profiles;
        try
        {
            profiles = _store.Load();
        }
        catch (ConfigurationException ex)
        {
            Banner = ex.Message;
            Raise(nameof(IsEmpty));
            return;
        }

        foreach (var profile in profiles)
        {
            Cameras.Add(CreateTile(profile));
        }

        Raise(nameof(IsEmpty));

        // Cleared before the zero-camera early return, not after it. Leaving it until later
        // meant a reload that found no cameras kept whatever stale error was on screen from the
        // previous attempt, so the first-run empty state could appear under a warning about a
        // camera that no longer exists.
        Banner = null;

        if (Cameras.Count == 0)
        {
            // First run, or every camera removed. No profile is ever created implicitly — the
            // empty state below is the whole first-run experience, and the user adds their own.
            DiagnosticLog.Write($"No cameras configured ({_store.FilePath}). Showing first-run empty state.");
            return;
        }

        await ConnectAllAsync().ConfigureAwait(true);
    }

    private async Task ConnectAllAsync()
    {
        // Sequential rather than parallel: each connection spawns a decoder process and an RTSP
        // session, and starting six at once on a busy Wi-Fi link makes every one of them slower
        // and harder to diagnose when one fails.
        //
        // Iterate a snapshot: each ConnectAsync awaits several network round trips, which yields
        // to the dispatcher, and the user can remove or edit a camera in that window. Enumerating
        // the live ObservableCollection would throw "Collection was modified" from MoveNext —
        // outside the try below, so it would take the application down.
        foreach (var camera in Cameras.ToList())
        {
            if (!Cameras.Contains(camera))
            {
                continue;
            }

            try
            {
                DiagnosticLog.Write($"Connecting '{camera.DisplayName}' at {camera.Address}…");
                await camera.ConnectAsync().ConfigureAwait(true);
                DiagnosticLog.Write($"Connected '{camera.DisplayName}'.");
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                DiagnosticLog.WriteException($"Connect '{camera.DisplayName}' failed", ex);
                Banner = $"{camera.DisplayName}: {ex.Message}";
            }
        }
    }

    private CameraTileViewModel CreateTile(CameraProfile profile) => new(
        new CameraSession(profile, _vault),
        _dispatcher,
        onEdit: EditCameraAsync,
        onRemove: RemoveCamera);

    private async Task AddCameraAsync()
    {
        if (RequestEditor is null)
        {
            return;
        }

        using var result = RequestEditor(null);
        if (result is null)
        {
            return;
        }

        await SaveCameraAsync(result).ConfigureAwait(true);
    }

    /// <summary>
    /// Awaited by the tile's edit command so failures reach the user.
    /// </summary>
    /// <remarks>
    /// Previously this was <c>_ = SaveCameraAsync(result)</c> from a void method. Because
    /// <c>SaveCameraAsync</c> is <c>async Task</c>, even the faults it throws before its first
    /// await are captured onto the discarded task rather than propagating — so a failed save
    /// (unreadable config, denied file, credential-store error) vanished silently and the user
    /// was left believing their edit had been applied.
    /// </remarks>
    private async Task EditCameraAsync(CameraTileViewModel tile)
    {
        if (RequestEditor is null)
        {
            return;
        }

        using var result = RequestEditor(tile.Profile);
        if (result is null)
        {
            return;
        }

        await SaveCameraAsync(result).ConfigureAwait(true);
    }

    private async Task SaveCameraAsync(CameraEditorResult result)
    {
        Banner = null;

        var profiles = _store.Load().ToList();
        var index = profiles.FindIndex(p => string.Equals(p.Id, result.Profile.Id, StringComparison.Ordinal));
        var isNewCamera = index < 0;

        // The credential is written first, so the config never references a camera whose password
        // is missing. The cost is the reverse window: if the config write then fails for a NEW
        // camera, its secret would be stranded in Credential Manager with nothing pointing at it
        // and no way for the user to find it. So that case is compensated below.
        var wroteCredential = false;
        if (result.Password is not null && result.UserName is not null)
        {
            _vault.Store(result.Profile.Id, result.UserName, result.Password.Reveal());
            wroteCredential = true;
        }

        if (isNewCamera)
        {
            profiles.Add(result.Profile);
        }
        else
        {
            profiles[index] = result.Profile;
        }

        try
        {
            _store.Save(profiles);
        }
        catch
        {
            if (wroteCredential && isNewCamera)
            {
                try
                {
                    _vault.Delete(result.Profile.Id);
                }
                catch (Exception cleanup) when (cleanup is not OutOfMemoryException)
                {
                    DiagnosticLog.WriteException("Rolling back an orphaned credential failed", cleanup);
                }
            }

            throw;
        }

        // Replace just this tile rather than reloading everything, so the other cameras keep
        // streaming while this one reconnects.
        var tile = CreateTile(result.Profile);
        var existing = Cameras.FirstOrDefault(
            c => string.Equals(c.Profile.Id, result.Profile.Id, StringComparison.Ordinal));

        if (existing is not null)
        {
            Cameras[Cameras.IndexOf(existing)] = tile;
            existing.Dispose();
        }
        else
        {
            Cameras.Add(tile);
        }

        Raise(nameof(IsEmpty));

        try
        {
            await tile.ConnectAsync().ConfigureAwait(true);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            DiagnosticLog.WriteException($"Connect '{tile.DisplayName}' after save failed", ex);
            Banner = $"{tile.DisplayName}: {ex.Message}";
        }
    }

    private void RemoveCamera(CameraTileViewModel tile)
    {
        var confirmed = RequestConfirmation?.Invoke(
            $"Remove '{tile.DisplayName}'?\n\nIts stored camera account password will also be deleted " +
            "from Windows Credential Manager. The camera itself is not changed.") ?? false;

        if (!confirmed)
        {
            return;
        }

        // Everything below touches disk and the credential store. RemoveCommand is a synchronous
        // RelayCommand whose Execute has no guard, and the app installs no dispatcher exception
        // handler, so an unhandled throw here would terminate the process on a button click —
        // for something as ordinary as the config file being locked by a sync client.
        try
        {
            var profiles = _store.Load()
                .Where(p => !string.Equals(p.Id, tile.Profile.Id, StringComparison.Ordinal))
                .ToList();

            _store.Save(profiles);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            DiagnosticLog.WriteException($"Removing '{tile.DisplayName}' failed", ex);
            Banner = $"Could not remove {tile.DisplayName}: {ex.Message}";
            return;
        }

        // The profile is gone from disk, so the tile must go regardless of what the vault does
        // next — otherwise it lingers on screen pointing at a camera that no longer exists.
        Cameras.Remove(tile);
        tile.Dispose();

        Raise(nameof(IsEmpty));
        Banner = null;

        try
        {
            _vault.Delete(tile.Profile.Id);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            DiagnosticLog.WriteException($"Deleting the credential for '{tile.DisplayName}' failed", ex);
            Banner = $"{tile.DisplayName} was removed, but its stored password could not be " +
                     $"deleted from Windows Credential Manager: {ex.Message}";
        }
        DiagnosticLog.Write($"Removed camera '{tile.DisplayName}'.");
    }

    public void Dispose()
    {
        foreach (var camera in Cameras)
        {
            camera.Dispose();
        }

        Cameras.Clear();
    }
}
