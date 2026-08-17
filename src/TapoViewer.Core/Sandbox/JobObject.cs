using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace TapoViewer.Core.Sandbox;

/// <summary>
/// A Windows Job Object that contains the decoder processes.
/// </summary>
/// <remarks>
/// Two jobs it does here. First, <c>KILL_ON_JOB_CLOSE</c> guarantees no orphans: if the UI
/// crashes or is killed, every decoder dies with it. Without this a hung libVLC child can sit
/// there holding an RTSP session and a camera connection indefinitely.
///
/// Second, it caps the damage a runaway or exploited decoder can do — a hard per-process memory
/// ceiling, a cap on how many processes it can spawn (so a shell popped inside the sandbox
/// cannot fork), and UI restrictions that block clipboard access and prevent it from shutting
/// Windows down.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class JobObject : IDisposable
{
    private const int InfoClassBasicUiRestrictions = 4;
    private const int InfoClassExtendedLimitInformation = 9;

    private const uint LimitActiveProcess = 0x00000008;
    private const uint LimitProcessMemory = 0x00000100;
    private const uint LimitDieOnUnhandledException = 0x00000400;
    private const uint LimitKillOnJobClose = 0x00002000;

    private const uint UiLimitReadClipboard = 0x00000010;
    private const uint UiLimitWriteClipboard = 0x00000020;
    private const uint UiLimitDisplaySettings = 0x00000040;
    private const uint UiLimitExitWindows = 0x00000080;
    private const uint UiLimitSystemParameters = 0x00000100;

    private IntPtr _handle;

    public JobObject()
    {
        _handle = CreateJobObject(IntPtr.Zero, null);
        if (_handle == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not create the sandbox job object.");
        }
    }

    public IntPtr Handle => _handle;

    /// <summary>Applies the containment limits. Call once, before any process is assigned.</summary>
    /// <param name="maxMemoryBytes">Hard per-process commit ceiling.</param>
    /// <param name="maxProcesses">Maximum simultaneous processes inside the job.</param>
    public void ApplyLimits(long maxMemoryBytes = 1536L * 1024 * 1024, int maxProcesses = 1)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxMemoryBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxProcesses);

        var extended = new JobObjectExtendedLimitInfo
        {
            BasicLimitInformation = new JobObjectBasicLimitInfo
            {
                LimitFlags = LimitKillOnJobClose
                    | LimitActiveProcess
                    | LimitProcessMemory
                    | LimitDieOnUnhandledException,
                ActiveProcessLimit = (uint)maxProcesses,
            },
            ProcessMemoryLimit = checked((UIntPtr)(ulong)maxMemoryBytes),
        };

        Set(InfoClassExtendedLimitInformation, extended, "limits");

        var ui = new JobObjectBasicUiRestrictions
        {
            UIRestrictionsClass = UiLimitReadClipboard
                | UiLimitWriteClipboard
                | UiLimitDisplaySettings
                | UiLimitExitWindows
                | UiLimitSystemParameters,
        };

        Set(InfoClassBasicUiRestrictions, ui, "UI restrictions");
    }

    public void Assign(IntPtr processHandle)
    {
        if (!AssignProcessToJobObject(_handle, processHandle))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Could not assign the decoder process to the sandbox job object.");
        }
    }

    private void Set<T>(int infoClass, T value, string what) where T : struct
    {
        var size = Marshal.SizeOf<T>();
        var buffer = Marshal.AllocHGlobal(size);

        try
        {
            Marshal.StructureToPtr(value, buffer, fDeleteOld: false);

            if (!SetInformationJobObject(_handle, infoClass, buffer, (uint)size))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    $"Could not apply sandbox {what}.");
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public void Dispose()
    {
        if (_handle != IntPtr.Zero)
        {
            // Closing the last handle triggers KILL_ON_JOB_CLOSE.
            CloseHandle(_handle);
            _handle = IntPtr.Zero;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInfo
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInfo
    {
        public JobObjectBasicLimitInfo BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicUiRestrictions
    {
        public uint UIRestrictionsClass;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr securityAttributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(
        IntPtr job,
        int infoClass,
        IntPtr info,
        uint infoLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}
