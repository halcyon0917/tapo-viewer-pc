using System.Globalization;
using System.IO;
using TapoViewer.Core.Configuration;

namespace TapoViewer.App.Services;

/// <summary>
/// Append-only local log for connection failures.
/// </summary>
/// <remarks>
/// A GUI swallows detail: the user sees "connection failed" and has nowhere to look. This writes
/// the underlying exception type and message to a file next to the config.
///
/// It logs failures and status, never credentials — <see cref="DecoderCommand"/> and
/// <see cref="Core.Rtsp.RtspTarget"/> both redact by construction, so nothing passed here can
/// carry a password unless someone works to put one there.
/// </remarks>
public static class DiagnosticLog
{
    private static readonly object Gate = new();
    private const long MaxBytes = 512 * 1024;

    public static string FilePath => Path.Combine(CameraConfigStore.DefaultDirectory, "app.log");

    public static void Write(string message)
    {
        try
        {
            lock (Gate)
            {
                Directory.CreateDirectory(CameraConfigStore.DefaultDirectory);

                // Keep it from growing without bound on a camera that fails every few seconds.
                var file = new FileInfo(FilePath);
                if (file.Exists && file.Length > MaxBytes)
                {
                    File.Delete(FilePath);
                }

                var stamp = DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture);
                File.AppendAllText(FilePath, $"[{stamp}] {message}{Environment.NewLine}");
            }
        }
        catch (IOException)
        {
            // Diagnostics must never be the reason the app fails.
        }
        catch (UnauthorizedAccessException)
        {
            // Ditto.
        }
    }

    public static void WriteException(string context, Exception ex)
    {
        Write($"{context}: {ex.GetType().FullName}: {ex.Message}");

        var inner = ex.InnerException;
        var depth = 0;
        while (inner is not null && depth < 5)
        {
            Write($"    inner[{depth}]: {inner.GetType().FullName}: {inner.Message}");
            inner = inner.InnerException;
            depth++;
        }

        if (ex.StackTrace is not null)
        {
            Write("    at " + ex.StackTrace.Trim().Replace(Environment.NewLine, Environment.NewLine + "    "));
        }
    }
}
