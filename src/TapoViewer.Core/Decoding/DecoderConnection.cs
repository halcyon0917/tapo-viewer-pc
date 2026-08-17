using System.Runtime.Versioning;
using System.Text;
using TapoViewer.Core.Rtsp;
using TapoViewer.Core.Sandbox;
using TapoViewer.Core.Security;

namespace TapoViewer.Core.Decoding;

/// <summary>
/// The UI-side handle on one sandboxed decoder process.
/// </summary>
/// <remarks>
/// Owns its own job object so each decoder is independently contained and independently killed;
/// one camera's decoder wedging or being killed for exceeding its memory ceiling does not disturb
/// the others.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class DecoderConnection : IDisposable
{
    private readonly JobObject _job;
    private readonly SandboxedProcess _process;
    private readonly string _executablePath;
    private readonly Thread _eventReader;
    private readonly Thread _errorReader;
    private readonly object _writeGate = new();

    private long _surfaceHandle;
    private bool _disposed;

    private DecoderConnection(JobObject job, SandboxedProcess process, string executablePath)
    {
        _job = job;
        _process = process;
        _executablePath = executablePath;

        _eventReader = new Thread(ReadEvents) { IsBackground = true, Name = "decoder-events" };
        _errorReader = new Thread(ReadErrors) { IsBackground = true, Name = "decoder-stderr" };

        _eventReader.Start();
        _errorReader.Start();
    }

    /// <summary>Raised on a background thread for every event the decoder reports.</summary>
    public event EventHandler<DecoderEvent>? EventReceived;

    /// <summary>Raised on a background thread with diagnostic lines from the decoder's stderr.</summary>
    public event EventHandler<string>? DiagnosticReceived;

    /// <summary>The decoder's window handle, or 0 until it reports one.</summary>
    public IntPtr SurfaceHandle => checked((IntPtr)Interlocked.Read(ref _surfaceHandle));

    public int ProcessId => _process.ProcessId;

    public SandboxIntegrity Integrity => _process.Integrity;

    public bool HasExited => _process.HasExited;

    public static DecoderConnection Start(
        string? decoderPath = null,
        SandboxIntegrity integrity = SandboxIntegrity.Low,
        long maxMemoryBytes = 1536L * 1024 * 1024)
    {
        var executable = DecoderLocator.LocateOrThrow(decoderPath);

        var job = new JobObject();
        try
        {
            job.ApplyLimits(maxMemoryBytes, maxProcesses: 1);

            var process = SandboxedProcess.Start(executable, "--host", integrity, job);
            return new DecoderConnection(job, process, executable);
        }
        catch
        {
            job.Dispose();
            throw;
        }
    }

    /// <summary>Waits for the decoder to report its window handle.</summary>
    public async Task<IntPtr> WaitForSurfaceAsync(TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        var deadline = DateTime.UtcNow + timeout;

        while (DateTime.UtcNow < deadline)
        {
            var handle = SurfaceHandle;
            if (handle != IntPtr.Zero)
            {
                return handle;
            }

            if (HasExited)
            {
                throw new InvalidOperationException(
                    "The decoder process exited before creating its surface " +
                    $"(exit code {_process.ExitCode?.ToString() ?? "unknown"}). " +
                    $"Executable: {_executablePath}");
            }

            await Task.Delay(25, cancellationToken).ConfigureAwait(false);
        }

        throw new TimeoutException("The decoder did not report a window handle in time.");
    }

    /// <summary>
    /// Starts playback, passing the camera-account credentials over the private stdin pipe.
    /// </summary>
    /// <remarks>
    /// The JSON line is composed by hand into a scratch buffer that is zeroed immediately after
    /// the write, rather than going through <c>JsonSerializer</c>. Serialising would materialise
    /// the password into an immutable managed string that cannot be erased and would linger in
    /// this process's heap — and this is the privileged process that can read the credential
    /// vault, so it is exactly where that exposure matters most.
    /// </remarks>
    public void Play(PinnedEndpoint endpoint, StreamQuality quality, string userName, ReadOnlySpan<char> password)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentException.ThrowIfNullOrEmpty(userName);
        ObjectDisposedException.ThrowIf(_disposed, this);

        var path = quality == StreamQuality.High ? "/stream1" : "/stream2";

        var buffer = new char[DecoderProtocol.MaxLineLength];
        var length = 0;

        try
        {
            Append(buffer, ref length, "{\"op\":\"play\",\"host\":\"");
            AppendEscaped(buffer, ref length, endpoint.Address.ToString());
            Append(buffer, ref length, "\",\"port\":");
            Append(buffer, ref length, endpoint.Port.ToString(System.Globalization.CultureInfo.InvariantCulture));
            Append(buffer, ref length, ",\"path\":\"");
            AppendEscaped(buffer, ref length, path);
            Append(buffer, ref length, "\",\"user\":\"");
            AppendEscaped(buffer, ref length, userName);
            Append(buffer, ref length, "\",\"pass\":\"");
            AppendEscaped(buffer, ref length, password);
            Append(buffer, ref length, "\"}");

            lock (_writeGate)
            {
                _process.StandardInput.Write(buffer, 0, length);
                _process.StandardInput.Write('\n');
                _process.StandardInput.Flush();
            }
        }
        finally
        {
            Array.Clear(buffer);
        }
    }

    public void Stop() => Send(new DecoderCommand { Op = DecoderCommand.OpStop });

    public void Resize(int x, int y, int width, int height) => Send(new DecoderCommand
    {
        Op = DecoderCommand.OpResize,
        X = x,
        Y = y,
        Width = Math.Max(width, 1),
        Height = Math.Max(height, 1),
    });

    public void Quit() => Send(new DecoderCommand { Op = DecoderCommand.OpQuit });

    private void Send(DecoderCommand command)
    {
        if (_disposed || HasExited)
        {
            return;
        }

        try
        {
            lock (_writeGate)
            {
                _process.StandardInput.WriteLine(DecoderProtocol.Serialize(command));
            }
        }
        catch (IOException)
        {
            // Decoder is gone; the event reader will surface the exit.
        }
        catch (ObjectDisposedException)
        {
            // Raced with Dispose.
        }
    }

    private void ReadEvents()
    {
        try
        {
            string? line;
            while ((line = _process.StandardOutput.ReadLine()) is not null)
            {
                var value = DecoderProtocol.ParseEvent(line);
                if (value is null)
                {
                    continue;
                }

                if (value.Event == DecoderEvent.EventReady)
                {
                    Interlocked.Exchange(ref _surfaceHandle, value.Hwnd);
                }

                EventReceived?.Invoke(this, value);
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            // Pipe closed on shutdown.
        }
    }

    private void ReadErrors()
    {
        try
        {
            string? line;
            while ((line = _process.StandardError.ReadLine()) is not null)
            {
                DiagnosticReceived?.Invoke(this, line);
            }
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            // Pipe closed on shutdown.
        }
    }

    private static void Append(char[] buffer, ref int length, string text)
    {
        if (length + text.Length > buffer.Length)
        {
            throw new InvalidOperationException("Decoder command exceeded the protocol line limit.");
        }

        text.CopyTo(0, buffer, length, text.Length);
        length += text.Length;
    }

    /// <summary>Appends a JSON-escaped string. Handles the characters that would break framing.</summary>
    private static void AppendEscaped(char[] buffer, ref int length, ReadOnlySpan<char> value)
    {
        foreach (var c in value)
        {
            switch (c)
            {
                case '"':
                    Append(buffer, ref length, "\\\"");
                    break;
                case '\\':
                    Append(buffer, ref length, "\\\\");
                    break;
                case '\n':
                    Append(buffer, ref length, "\\n");
                    break;
                case '\r':
                    Append(buffer, ref length, "\\r");
                    break;
                case '\t':
                    Append(buffer, ref length, "\\t");
                    break;
                default:
                    if (char.IsControl(c))
                    {
                        Append(buffer, ref length, "\\u");
                        Append(buffer, ref length, ((int)c).ToString("x4", System.Globalization.CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        if (length + 1 > buffer.Length)
                        {
                            throw new InvalidOperationException("Decoder command exceeded the protocol line limit.");
                        }

                        buffer[length++] = c;
                    }

                    break;
            }
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
            Quit();
            _process.WaitForExit(1500);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            // Already gone.
        }

        _process.Kill();
        _process.Dispose();

        // Closing the job handle enforces kill-on-close for anything still alive inside it.
        _job.Dispose();
    }
}
