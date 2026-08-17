using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace TapoViewer.Core.Sandbox;

/// <summary>
/// Reads back the actual integrity level of a running process.
/// </summary>
/// <remarks>
/// Exists so the sandbox can be verified rather than assumed. Setting a token label and having
/// it take effect are different things, and a silently-failed <c>SetTokenInformation</c> would
/// leave the decoder running at full user privilege while every comment in the codebase claimed
/// otherwise. This is what turns that claim into a measurement.
/// </remarks>
[SupportedOSPlatform("windows")]
public static class SandboxInspector
{
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint TokenQuery = 0x0008;
    private const int TokenIntegrityLevel = 25;
    private const int ErrorInsufficientBuffer = 122;

    public const string LowIntegrity = "S-1-16-4096";
    public const string MediumIntegrity = "S-1-16-8192";
    public const string HighIntegrity = "S-1-16-12288";

    /// <summary>Returns the integrity SID of the given process, e.g. <c>S-1-16-4096</c>.</summary>
    public static string GetIntegritySid(int processId)
    {
        var process = OpenProcess(ProcessQueryLimitedInformation, false, processId);
        if (process == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"Could not open process {processId}.");
        }

        try
        {
            if (!OpenProcessToken(process, TokenQuery, out var token))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    $"Could not open the token of process {processId}.");
            }

            try
            {
                GetTokenInformation(token, TokenIntegrityLevel, IntPtr.Zero, 0, out var needed);

                var error = Marshal.GetLastWin32Error();
                if (needed == 0)
                {
                    throw new Win32Exception(error, "Could not size the token integrity information.");
                }

                var buffer = Marshal.AllocHGlobal((int)needed);
                try
                {
                    if (!GetTokenInformation(token, TokenIntegrityLevel, buffer, needed, out _))
                    {
                        throw new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            "Could not read the token integrity information.");
                    }

                    var label = Marshal.PtrToStructure<TokenMandatoryLabel>(buffer);
                    if (!ConvertSidToStringSid(label.Sid, out var sidString))
                    {
                        throw new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            "Could not convert the integrity SID to text.");
                    }

                    return sidString;
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            finally
            {
                CloseHandle(token);
            }
        }
        finally
        {
            CloseHandle(process);
        }
    }

    /// <summary>Maps an integrity SID to a readable name.</summary>
    public static string Describe(string integritySid) => integritySid switch
    {
        LowIntegrity => "Low",
        MediumIntegrity => "Medium",
        HighIntegrity => "High",
        _ => integritySid,
    };

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenMandatoryLabel
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        int processId);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr process, uint desiredAccess, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(
        IntPtr token,
        int informationClass,
        IntPtr information,
        uint length,
        out uint returnLength);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertSidToStringSid(IntPtr sid, out string sidString);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}
