using System.Globalization;
using System.Windows;
using System.Windows.Media;
using TapoViewer.App.Services;
using TapoViewer.Core.Configuration;
using TapoViewer.Core.Rtsp;
using TapoViewer.Core.Security;

namespace TapoViewer.App.Dialogs;

/// <summary>What the editor produced. Owns the password until the caller disposes it.</summary>
public sealed class CameraEditorResult : IDisposable
{
    public required CameraProfile Profile { get; init; }

    /// <summary>Camera-account username, or <see langword="null"/> to keep the stored one.</summary>
    public string? UserName { get; init; }

    /// <summary>New password, or <see langword="null"/> to keep the stored one.</summary>
    public Secret? Password { get; init; }

    public void Dispose() => Password?.Dispose();
}

/// <summary>
/// Add or edit one camera.
/// </summary>
/// <remarks>
/// The password is read from <c>PasswordBox.SecurePassword</c> and marshalled straight into a
/// <see cref="Secret"/>. <c>PasswordBox.Password</c> is deliberately never touched: it returns an
/// immutable managed string that cannot be erased, and binding it to a view-model property — the
/// usual MVVM shortcut — would leave the plaintext sitting in the heap for the lifetime of the
/// dialog and beyond.
///
/// When editing, a blank password field means "keep what is already in the vault" rather than
/// "set an empty password".
/// </remarks>
public partial class CameraEditorWindow : Window
{
    private readonly CameraProfile? _original;

    public CameraEditorWindow(CameraProfile? existing = null)
    {
        InitializeComponent();

        _original = existing;
        Title = existing is null ? "Add camera" : $"Edit {existing.DisplayName}";

        if (existing is not null)
        {
            NameBox.Text = existing.DisplayName;
            HostBox.Text = existing.Host;
            RtspPortBox.Text = existing.RtspPort.ToString(CultureInfo.InvariantCulture);
            OnvifPortBox.Text = existing.OnvifPort.ToString(CultureInfo.InvariantCulture);
            QualityBox.SelectedIndex = existing.PreferredQuality == StreamQuality.Standard ? 1 : 0;
            MotionBox.IsChecked = existing.MotionEventsEnabled;
            PasswordHint.Text = "Leave blank to keep the stored password.";
        }
        else
        {
            MotionBox.IsChecked = true;
        }

        Loaded += (_, _) => NameBox.Focus();
    }

    /// <summary>Set when the dialog is accepted.</summary>
    public CameraEditorResult? Result { get; private set; }

    private async void OnTestClick(object sender, RoutedEventArgs e)
    {
        using var password = ReadPassword();

        if (!TryReadFields(password is not null, out var profile, out var userName, out var error))
        {
            ShowMessage(error!, success: false);
            return;
        }

        if (password is null)
        {
            ShowMessage(
                _original is null
                    ? "Enter the camera account password to test the connection."
                    : "Enter the password to test. The stored one cannot be read back for testing.",
                success: false);

            return;
        }

        TestButton.IsEnabled = false;
        SaveButton.IsEnabled = false;
        ShowMessage("Testing…", success: true);

        try
        {
            var result = await CameraTester.TestAsync(profile!.Host, profile.OnvifPort, userName!, password)
                .ConfigureAwait(true);

            ShowMessage(result.Message, result.Success);

            if (result.Success)
            {
                // Reflect what the camera actually reported rather than what was guessed.
                MotionBox.IsChecked = result.SupportsEvents;

                if (result.RtspPort is int port && port != profile.RtspPort)
                {
                    RtspPortBox.Text = port.ToString(CultureInfo.InvariantCulture);
                    ShowMessage($"{result.Message} (RTSP port corrected to {port}.)", success: true);
                }
            }
        }
        finally
        {
            TestButton.IsEnabled = true;
            SaveButton.IsEnabled = true;
        }
    }

    private void OnSaveClick(object sender, RoutedEventArgs e)
    {
        var password = ReadPassword();

        if (!TryReadFields(password is not null, out var profile, out var userName, out var error))
        {
            password?.Dispose();
            ShowMessage(error!, success: false);
            return;
        }

        if (_original is null && password is null)
        {
            ShowMessage("A new camera needs a camera account username and password.", success: false);
            return;
        }

        Result = new CameraEditorResult
        {
            Profile = profile!,
            UserName = password is null ? null : userName,
            Password = password,
        };

        DialogResult = true;
        Close();
    }

    private void OnCancelClick(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }

    /// <summary>
    /// Returns <see langword="null"/> when the field is blank.
    /// </summary>
    /// <remarks>
    /// <c>PasswordBox.SecurePassword</c> hands back a fresh copy on every access, so each call
    /// must dispose what it gets. Read it once per operation and pass the result around rather
    /// than touching the property repeatedly.
    /// </remarks>
    private Secret? ReadPassword()
    {
        using var secure = PasswordBox.SecurePassword;
        return secure.Length == 0 ? null : Secret.FromSecureString(secure);
    }

    private bool TryReadFields(
        bool hasPassword,
        out CameraProfile? profile,
        out string? userName,
        out string? error)
    {
        profile = null;
        userName = UserBox.Text.Trim();
        error = null;

        var name = NameBox.Text.Trim();
        if (name.Length == 0)
        {
            error = "Enter a name for this camera.";
            return false;
        }

        var host = HostBox.Text.Trim();
        if (host.Length == 0)
        {
            error = "Enter the camera's LAN address.";
            return false;
        }

        if (!int.TryParse(RtspPortBox.Text.Trim(), out var rtspPort) || rtspPort is < 1 or > 65535)
        {
            error = "RTSP port must be a number between 1 and 65535.";
            return false;
        }

        if (!int.TryParse(OnvifPortBox.Text.Trim(), out var onvifPort) || onvifPort is < 1 or > 65535)
        {
            error = "ONVIF port must be a number between 1 and 65535.";
            return false;
        }

        if (userName.Length == 0 && (_original is null || hasPassword))
        {
            error = "Enter the camera account username.";
            return false;
        }

        var candidate = new CameraProfile
        {
            // Keep the id when editing: it is the vault key, and changing it would orphan the
            // stored credential.
            Id = _original?.Id ?? CameraProfile.NewId(),
            DisplayName = name,
            Host = host,
            RtspPort = rtspPort,
            OnvifPort = onvifPort,
            PreferredQuality = QualityBox.SelectedIndex == 1 ? StreamQuality.Standard : StreamQuality.High,
            MotionEventsEnabled = MotionBox.IsChecked == true,
        };

        var invalid = candidate.Validate();
        if (invalid is not null)
        {
            error = invalid;
            return false;
        }

        profile = candidate;
        return true;
    }

    private void ShowMessage(string message, bool success)
    {
        MessageText.Text = message;
        MessageText.Foreground = (Brush)FindResource("Ink");
        MessagePanel.Background = success
            ? new SolidColorBrush(Color.FromRgb(0x14, 0x2A, 0x1E))
            : new SolidColorBrush(Color.FromRgb(0x2E, 0x16, 0x18));
        MessagePanel.Visibility = Visibility.Visible;
    }
}
