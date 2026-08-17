namespace TapoViewer.Core.Security;

/// <summary>A camera account username paired with its password.</summary>
public sealed class CameraCredential : IDisposable
{
    public CameraCredential(string userName, Secret password)
    {
        ArgumentException.ThrowIfNullOrEmpty(userName);
        ArgumentNullException.ThrowIfNull(password);

        UserName = userName;
        Password = password;
    }

    public string UserName { get; }

    public Secret Password { get; }

    public void Dispose() => Password.Dispose();
}

/// <summary>
/// Stores camera-account credentials outside of this application's own files.
/// </summary>
/// <remarks>
/// The app never writes passwords to its config. Config holds only a stable camera id; the
/// secret lives in the OS credential store, encrypted at rest under the user's logon and
/// inaccessible to other user accounts on the machine. That way a leaked or synced config file,
/// a backup, or a support bundle carries no secrets at all.
/// </remarks>
public interface ICredentialVault
{
    void Store(string cameraId, string userName, ReadOnlySpan<char> password);

    /// <summary>Returns <see langword="null"/> when no credential is stored for the camera.</summary>
    CameraCredential? Retrieve(string cameraId);

    /// <summary>Returns <see langword="false"/> when there was nothing to delete.</summary>
    bool Delete(string cameraId);
}
