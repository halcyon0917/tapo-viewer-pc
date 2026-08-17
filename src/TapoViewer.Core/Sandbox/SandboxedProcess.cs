using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace TapoViewer.Core.Sandbox;

/// <summary>Integrity level to run a sandboxed child at.</summary>
public enum SandboxIntegrity
{
    /// <summary>
    /// S-1-16-4096. Cannot write to the user's files or registry, cannot send window messages to
    /// higher-integrity windows, cannot open higher-integrity processes.
    /// </summary>
    Low,

    /// <summary>S-1-16-8192 — the caller's normal level. Process isolation and the job only.</summary>
    Medium,
}

/// <summary>
/// Launches a child process at a chosen integrity level, inside a job object, with its standard
/// streams wired to private inherited pipes.
/// </summary>
/// <remarks>
/// <see cref="System.Diagnostics.Process"/> cannot do this — it offers no way to supply a token —
/// so the process is created through <c>CreateProcessAsUser</c> with a duplicate of our own token
/// whose integrity label has been lowered. Lowering your own token this way needs no special
/// privilege; it is the same mechanism browsers use for renderer processes.
///
/// The child is created suspended, assigned to the job, and only then resumed, so the job's limits
/// are in force before it executes a single instruction.
///
/// Why this matters: libVLC and its demuxers are a large body of C parsing hostile input from a
/// device on an untrusted network. Assume one day it is exploitable. At low integrity the payload
/// lands in a process that cannot write to the user's documents, cannot read the credential vault,
/// cannot inject into the UI process, and dies when the job handle closes.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class SandboxedProcess : IDisposable
{
    private const uint TokenAssignPrimary = 0x0001;
    private const uint TokenDuplicate = 0x0002;
    private const uint TokenQuery = 0x0008;
    private const uint TokenAdjustDefault = 0x0020;
    private const uint TokenAdjustSessionId = 0x0100;
    private const uint TokenAllAccess = 0x000F01FF;

    private const int TokenPrimary = 1;
    private const int SecurityImpersonation = 2;
    private const int TokenIntegrityLevel = 25;
    private const uint SeGroupIntegrity = 0x00000020;

    private const uint CreateSuspended = 0x00000004;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint CreateNoWindow = 0x08000000;
    private const uint StartfUseStdHandles = 0x00000100;
    private const uint HandleFlagInherit = 0x00000001;
    private const uint StillActive = 259;

    private const string LowIntegritySid = "S-1-16-4096";
    private const string MediumIntegritySid = "S-1-16-8192";

    private IntPtr _processHandle;
    private IntPtr _threadHandle;
    private bool _disposed;

    private SandboxedProcess(
        IntPtr processHandle,
        IntPtr threadHandle,
        int processId,
        StreamWriter standardInput,
        StreamReader standardOutput,
        StreamReader standardError,
        SandboxIntegrity integrity)
    {
        _processHandle = processHandle;
        _threadHandle = threadHandle;
        ProcessId = processId;
        StandardInput = standardInput;
        StandardOutput = standardOutput;
        StandardError = standardError;
        Integrity = integrity;
    }

    public int ProcessId { get; }

    public SandboxIntegrity Integrity { get; }

    /// <summary>Write commands here. Private to this process pair.</summary>
    public StreamWriter StandardInput { get; }

    public StreamReader StandardOutput { get; }

    public StreamReader StandardError { get; }

    public bool HasExited => !_disposed
        && _processHandle != IntPtr.Zero
        && GetExitCodeProcess(_processHandle, out var code)
        && code != StillActive;

    /// <summary>Exit code, or <see langword="null"/> while the process is still running.</summary>
    public uint? ExitCode => _processHandle != IntPtr.Zero
        && GetExitCodeProcess(_processHandle, out var code)
        && code != StillActive
            ? code
            : null;

    public static SandboxedProcess Start(
        string executablePath,
        string arguments,
        SandboxIntegrity integrity,
        JobObject job)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        ArgumentNullException.ThrowIfNull(job);

        if (!File.Exists(executablePath))
        {
            throw new FileNotFoundException("Decoder executable not found.", executablePath);
        }

        var inheritable = new SecurityAttributes
        {
            Length = Marshal.SizeOf<SecurityAttributes>(),
            InheritHandle = true,
        };

        SafeFileHandle? stdinRead = null, stdinWrite = null;
        SafeFileHandle? stdoutRead = null, stdoutWrite = null;
        SafeFileHandle? stderrRead = null, stderrWrite = null;
        var token = IntPtr.Zero;

        try
        {
            CreatePipeChecked(out stdinRead, out stdinWrite, inheritable, parentEnd: PipeEnd.Write);
            CreatePipeChecked(out stdoutRead, out stdoutWrite, inheritable, parentEnd: PipeEnd.Read);
            CreatePipeChecked(out stderrRead, out stderrWrite, inheritable, parentEnd: PipeEnd.Read);

            token = CreateTokenAt(integrity);

            var startup = new StartupInfo
            {
                cb = Marshal.SizeOf<StartupInfo>(),
                dwFlags = StartfUseStdHandles,
                hStdInput = stdinRead.DangerousGetHandle(),
                hStdOutput = stdoutWrite.DangerousGetHandle(),
                hStdError = stderrWrite.DangerousGetHandle(),
            };

            // argv[0] must be quoted or a space in the path silently truncates the target.
            // A char[] rather than StringBuilder: CreateProcessW is documented as possibly
            // *writing* to lpCommandLine, so the buffer must be mutable, and char[] avoids the
            // StringBuilder marshalling layer (CA1838). The terminator must be explicit.
            var commandLine = $"\"{executablePath}\" {arguments}\0".ToCharArray();

            var created = CreateProcessAsUser(
                token,
                null,
                commandLine,
                IntPtr.Zero,
                IntPtr.Zero,
                bInheritHandles: true,
                CreateSuspended | CreateNoWindow | CreateUnicodeEnvironment,
                IntPtr.Zero,
                Path.GetDirectoryName(executablePath),
                ref startup,
                out var processInfo);

            if (!created)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    $"Could not launch the decoder at {integrity} integrity.");
            }

            try
            {
                // Limits must bind before the child runs.
                job.Assign(processInfo.hProcess);

                if (ResumeThread(processInfo.hThread) == unchecked((uint)-1))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "Could not resume the sandboxed decoder.");
                }
            }
            catch
            {
                TerminateProcess(processInfo.hProcess, 1);
                CloseHandle(processInfo.hThread);
                CloseHandle(processInfo.hProcess);
                throw;
            }

            // The child owns its ends now; ours must close or we will never see EOF.
            stdinRead.Dispose();
            stdoutWrite.Dispose();
            stderrWrite.Dispose();

            var input = new StreamWriter(new FileStream(stdinWrite, FileAccess.Write), new UTF8Encoding(false))
            {
                AutoFlush = true,
            };

            var output = new StreamReader(new FileStream(stdoutRead, FileAccess.Read), Encoding.UTF8);
            var error = new StreamReader(new FileStream(stderrRead, FileAccess.Read), Encoding.UTF8);

            // Ownership transferred to the FileStreams.
            stdinWrite = null;
            stdoutRead = null;
            stderrRead = null;
            stdinRead = null;
            stdoutWrite = null;
            stderrWrite = null;

            return new SandboxedProcess(
                processInfo.hProcess,
                processInfo.hThread,
                processInfo.dwProcessId,
                input,
                output,
                error,
                integrity);
        }
        finally
        {
            if (token != IntPtr.Zero)
            {
                CloseHandle(token);
            }

            stdinRead?.Dispose();
            stdinWrite?.Dispose();
            stdoutRead?.Dispose();
            stdoutWrite?.Dispose();
            stderrRead?.Dispose();
            stderrWrite?.Dispose();
        }
    }

    /// <summary>Duplicates our own token and lowers its mandatory integrity label.</summary>
    private static IntPtr CreateTokenAt(SandboxIntegrity integrity)
    {
        if (!OpenProcessToken(
                Process.GetCurrentProcess().Handle,
                TokenDuplicate | TokenQuery | TokenAssignPrimary | TokenAdjustDefault | TokenAdjustSessionId,
                out var current))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not open the current process token.");
        }

        var duplicate = IntPtr.Zero;
        var sid = IntPtr.Zero;

        try
        {
            if (!DuplicateTokenEx(
                    current,
                    TokenAllAccess,
                    IntPtr.Zero,
                    SecurityImpersonation,
                    TokenPrimary,
                    out duplicate))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not duplicate the process token.");
            }

            var sidString = integrity == SandboxIntegrity.Low ? LowIntegritySid : MediumIntegritySid;
            if (!ConvertStringSidToSid(sidString, out sid))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    $"Could not build the integrity SID {sidString}.");
            }

            var label = new TokenMandatoryLabel
            {
                Label = new SidAndAttributes
                {
                    Sid = sid,
                    Attributes = SeGroupIntegrity,
                },
            };

            var size = Marshal.SizeOf<TokenMandatoryLabel>();
            var buffer = Marshal.AllocHGlobal(size);

            try
            {
                Marshal.StructureToPtr(label, buffer, fDeleteOld: false);

                if (!SetTokenInformation(duplicate, TokenIntegrityLevel, buffer, (uint)(size + GetLengthSid(sid))))
                {
                    var error = Marshal.GetLastWin32Error();
                    throw new Win32Exception(
                        error,
                        $"Could not set the token integrity level to {integrity} (Win32 error {error}).");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

            var result = duplicate;
            duplicate = IntPtr.Zero;
            return result;
        }
        finally
        {
            if (duplicate != IntPtr.Zero)
            {
                CloseHandle(duplicate);
            }

            if (sid != IntPtr.Zero)
            {
                LocalFree(sid);
            }

            CloseHandle(current);
        }
    }

    private enum PipeEnd
    {
        Read,
        Write,
    }

    private static void CreatePipeChecked(
        out SafeFileHandle read,
        out SafeFileHandle write,
        SecurityAttributes attributes,
        PipeEnd parentEnd)
    {
        if (!CreatePipe(out read, out write, ref attributes, 0))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not create a sandbox pipe.");
        }

        // Our own end must not be inheritable, or a later child would receive a duplicate and
        // hold the pipe open, so we would never observe EOF.
        var parent = parentEnd == PipeEnd.Read ? read : write;
        if (!SetHandleInformation(parent.DangerousGetHandle(), HandleFlagInherit, 0))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not clear pipe handle inheritance.");
        }
    }

    public bool WaitForExit(int milliseconds)
        => _processHandle != IntPtr.Zero && WaitForSingleObject(_processHandle, (uint)milliseconds) == 0;

    public void Kill()
    {
        if (_processHandle != IntPtr.Zero && !HasExited)
        {
            TerminateProcess(_processHandle, 1);
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        try
        {
            StandardInput.Dispose();
        }
        catch (IOException)
        {
            // The child may already be gone; nothing useful to do.
        }

        StandardOutput.Dispose();
        StandardError.Dispose();

        if (_threadHandle != IntPtr.Zero)
        {
            CloseHandle(_threadHandle);
            _threadHandle = IntPtr.Zero;
        }

        if (_processHandle != IntPtr.Zero)
        {
            CloseHandle(_processHandle);
            _processHandle = IntPtr.Zero;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public IntPtr SecurityDescriptor;

        [MarshalAs(UnmanagedType.Bool)]
        public bool InheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public int cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenMandatoryLabel
    {
        public SidAndAttributes Label;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreatePipe(
        out SafeFileHandle readPipe,
        out SafeFileHandle writePipe,
        ref SecurityAttributes attributes,
        int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr process, uint desiredAccess, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateTokenEx(
        IntPtr existingToken,
        uint desiredAccess,
        IntPtr attributes,
        int impersonationLevel,
        int tokenType,
        out IntPtr newToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetTokenInformation(
        IntPtr token,
        int informationClass,
        IntPtr information,
        uint informationLength);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSidToSid(string sid, out IntPtr convertedSid);

    [DllImport("advapi32.dll")]
    private static extern int GetLengthSid(IntPtr sid);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessAsUser(
        IntPtr token,
        string? applicationName,
        char[] commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles,
        uint creationFlags,
        IntPtr environment,
        string? currentDirectory,
        ref StartupInfo startupInfo,
        out ProcessInformation processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr memory);
}
