using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace TapoViewer.Core.Security;

/// <summary>
/// <see cref="ICredentialVault"/> backed by the Windows Credential Manager.
/// </summary>
/// <remarks>
/// Chosen over a DPAPI-encrypted file of our own: both bind the secret to the user's logon, but
/// the credential store leaves no file for us to accidentally back up, sync, ship in a crash
/// bundle, or mis-ACL. Users can also audit and revoke entries themselves via
/// <c>rundll32 keymgr.dll,KRShowKeyMgr</c>.
///
/// Persistence is <c>CRED_PERSIST_LOCAL_MACHINE</c>: survives reboot, stays scoped to this
/// Windows user, and never roams to another machine.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class WindowsCredentialVault : ICredentialVault
{
    private const string TargetPrefix = "TapoViewer:camera:";

    private const uint CredTypeGeneric = 1;
    private const uint CredPersistLocalMachine = 2;
    private const int ErrorNotFound = 1168;

    /// <summary>CRED_MAX_CREDENTIAL_BLOB_SIZE (5 * 512 bytes).</summary>
    private const int MaxBlobBytes = 2560;

    public void Store(string cameraId, string userName, ReadOnlySpan<char> password)
    {
        var target = BuildTarget(cameraId);
        ArgumentException.ThrowIfNullOrEmpty(userName);

        var blobBytes = checked(password.Length * sizeof(char));
        if (blobBytes > MaxBlobBytes)
        {
            throw new ArgumentException(
                $"Password exceeds the {MaxBlobBytes / sizeof(char)}-character Windows limit.",
                nameof(password));
        }

        var blob = Marshal.AllocHGlobal(Math.Max(blobBytes, 1));
        var targetPtr = IntPtr.Zero;
        var userPtr = IntPtr.Zero;

        try
        {
            for (var i = 0; i < password.Length; i++)
            {
                Marshal.WriteInt16(blob, i * sizeof(char), (short)password[i]);
            }

            targetPtr = Marshal.StringToCoTaskMemUni(target);
            userPtr = Marshal.StringToCoTaskMemUni(userName);

            var credential = new Credential
            {
                Type = CredTypeGeneric,
                TargetName = targetPtr,
                CredentialBlobSize = (uint)blobBytes,
                CredentialBlob = blob,
                Persist = CredPersistLocalMachine,
                UserName = userPtr,
            };

            if (!CredWrite(ref credential, 0))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    $"Failed to store the credential for camera '{cameraId}'.");
            }
        }
        finally
        {
            // Zero the plaintext before handing the pages back to the allocator.
            for (var i = 0; i < password.Length; i++)
            {
                Marshal.WriteInt16(blob, i * sizeof(char), 0);
            }

            Marshal.FreeHGlobal(blob);

            if (targetPtr != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(targetPtr);
            }

            if (userPtr != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(userPtr);
            }
        }
    }

    public CameraCredential? Retrieve(string cameraId)
    {
        var target = BuildTarget(cameraId);

        if (!CredRead(target, CredTypeGeneric, 0, out var handle))
        {
            var error = Marshal.GetLastWin32Error();
            if (error == ErrorNotFound)
            {
                return null;
            }

            throw new Win32Exception(
                error,
                $"Failed to read the credential for camera '{cameraId}'.");
        }

        try
        {
            var credential = Marshal.PtrToStructure<Credential>(handle);

            var userName = credential.UserName == IntPtr.Zero
                ? string.Empty
                : Marshal.PtrToStringUni(credential.UserName) ?? string.Empty;

            if (userName.Length == 0)
            {
                throw new InvalidOperationException(
                    $"Stored credential for camera '{cameraId}' has no username.");
            }

            var charCount = (int)(credential.CredentialBlobSize / sizeof(char));
            var password = credential.CredentialBlob == IntPtr.Zero || charCount == 0
                ? Secret.FromChars(ReadOnlySpan<char>.Empty)
                : Secret.FromNativeUtf16(credential.CredentialBlob, charCount);

            return new CameraCredential(userName, password);
        }
        finally
        {
            CredFree(handle);
        }
    }

    public bool Delete(string cameraId)
    {
        var target = BuildTarget(cameraId);

        if (CredDelete(target, CredTypeGeneric, 0))
        {
            return true;
        }

        var error = Marshal.GetLastWin32Error();
        if (error == ErrorNotFound)
        {
            return false;
        }

        throw new Win32Exception(
            error,
            $"Failed to delete the credential for camera '{cameraId}'.");
    }

    private static string BuildTarget(string cameraId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cameraId);

        // The id becomes part of a global namespace key, so keep it to characters that cannot
        // be used to collide with or impersonate another application's entries.
        foreach (var c in cameraId)
        {
            if (!char.IsAsciiLetterOrDigit(c) && c != '-' && c != '_')
            {
                throw new ArgumentException(
                    "Camera id must contain only ASCII letters, digits, '-' or '_'.",
                    nameof(cameraId));
            }
        }

        return TargetPrefix + cameraId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Credential
    {
        public uint Flags;
        public uint Type;
        public IntPtr TargetName;
        public IntPtr Comment;
        public long LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public IntPtr TargetAlias;
        public IntPtr UserName;
    }

    [DllImport("advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredWrite(ref Credential credential, uint flags);

    [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredRead(string target, uint type, uint reservedFlag, out IntPtr credential);

    [DllImport("advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredDelete(string target, uint type, uint flags);

    [DllImport("advapi32.dll", EntryPoint = "CredFree")]
    private static extern void CredFree(IntPtr credential);
}
