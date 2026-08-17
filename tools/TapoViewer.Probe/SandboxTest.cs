using System.Diagnostics;
using TapoViewer.Core.Configuration;
using TapoViewer.Core.Decoding;
using TapoViewer.Core.Rtsp;
using TapoViewer.Core.Sandbox;
using TapoViewer.Core.Security;

namespace TapoViewer.Probe;

/// <summary>
/// Launches the decoder in its sandbox, plays a stream, and reports what actually happened.
/// </summary>
/// <remarks>
/// The point is measurement, not demonstration. It reads the child's real token integrity level
/// after launch, so "the decoder runs at low integrity" is a verified fact rather than an
/// intention, and it reports whether playback survives the sandbox — low integrity can break GPU
/// access, so hardware decode has to be checked, not assumed.
/// </remarks>
internal static class SandboxTest
{
    internal static int Run(string[] args)
    {
        var integrity = ReadString(args, "--integrity", "low").Equals("medium", StringComparison.OrdinalIgnoreCase)
            ? SandboxIntegrity.Medium
            : SandboxIntegrity.Low;

        var seconds = ReadInt(args, "--seconds", 10);

        var store = new CameraConfigStore();
        var cameras = store.Load();
        if (cameras.Count == 0)
        {
            Console.Error.WriteLine($"No cameras configured in {store.FilePath}. Run the probe first.");
            return 2;
        }

        var camera = cameras[0];

        var vault = new WindowsCredentialVault();
        using var credential = vault.Retrieve(camera.Id);
        if (credential is null)
        {
            Console.Error.WriteLine($"No stored credential for '{camera.Id}'. Run the probe first.");
            return 3;
        }

        var decoderPath = LocateDecoder(args);
        if (decoderPath is null)
        {
            Console.Error.WriteLine(
                "Could not find TapoViewer.Decoder.exe. Build it, or pass --decoder <path>.");
            return 4;
        }

        Console.WriteLine($"Decoder   : {decoderPath}");
        Console.WriteLine($"Camera    : {camera.DisplayName} ({camera.Host}:{camera.RtspPort})");
        Console.WriteLine($"Requested : {integrity} integrity");
        Console.WriteLine();

        using var job = new JobObject();
        job.ApplyLimits(maxMemoryBytes: 1536L * 1024 * 1024, maxProcesses: 1);
        Console.WriteLine("  Job object created with kill-on-close, 1-process and 1.5 GiB limits.");

        using var child = SandboxedProcess.Start(decoderPath, "--host", integrity, job);
        Console.WriteLine($"  Decoder launched, pid {child.ProcessId}.");

        // The measurement that matters.
        var actualSid = SandboxInspector.GetIntegritySid(child.ProcessId);
        var expectedSid = integrity == SandboxIntegrity.Low
            ? SandboxInspector.LowIntegrity
            : SandboxInspector.MediumIntegrity;

        var integrityMatches = string.Equals(actualSid, expectedSid, StringComparison.Ordinal);
        Console.WriteLine(
            $"  Actual integrity: {SandboxInspector.Describe(actualSid)} ({actualSid}) " +
            $"{(integrityMatches ? "-- matches request" : "-- MISMATCH, expected " + expectedSid)}");

        var parentSid = SandboxInspector.GetIntegritySid(Environment.ProcessId);
        Console.WriteLine($"  This process   : {SandboxInspector.Describe(parentSid)} ({parentSid})");
        Console.WriteLine();

        var errors = new List<string>();
        var states = new List<string>();
        long hwnd = 0;

        var reader = new Thread(() =>
        {
            string? line;
            while ((line = child.StandardOutput.ReadLine()) is not null)
            {
                var value = DecoderProtocol.ParseEvent(line);
                if (value is null)
                {
                    continue;
                }

                switch (value.Event)
                {
                    case DecoderEvent.EventReady:
                        Interlocked.Exchange(ref hwnd, value.Hwnd);
                        break;

                    case DecoderEvent.EventState:
                        lock (states)
                        {
                            states.Add(value.Value ?? "?");
                        }

                        break;

                    case DecoderEvent.EventError:
                        lock (errors)
                        {
                            errors.Add(value.Message ?? "unknown");
                        }

                        break;
                }
            }
        })
        {
            IsBackground = true,
        };

        reader.Start();

        var stderrDrain = new Thread(() =>
        {
            string? line;
            while ((line = child.StandardError.ReadLine()) is not null)
            {
                lock (errors)
                {
                    errors.Add("[stderr] " + line);
                }
            }
        })
        {
            IsBackground = true,
        };

        stderrDrain.Start();

        Console.Write("  Waiting for the decoder window handle ... ");
        var readyDeadline = Stopwatch.StartNew();
        while (Interlocked.Read(ref hwnd) == 0 && readyDeadline.Elapsed < TimeSpan.FromSeconds(10))
        {
            if (child.HasExited)
            {
                Console.WriteLine("child exited early");
                DumpErrors(errors);
                return 5;
            }

            Thread.Sleep(50);
        }

        var surface = Interlocked.Read(ref hwnd);
        if (surface == 0)
        {
            Console.WriteLine("timed out");
            DumpErrors(errors);
            return 6;
        }

        Console.WriteLine($"OK  hwnd=0x{surface:X}");

        var endpoint = HostGuard.Pin(camera.Host, camera.RtspPort);
        var quality = camera.PreferredQuality == StreamQuality.Standard ? "/stream2" : "/stream1";

        // Credentials cross to the child over its inherited stdin, never on its command line.
        var play = new DecoderCommand
        {
            Op = DecoderCommand.OpPlay,
            Host = endpoint.Address.ToString(),
            Port = endpoint.Port,
            Path = quality,
            User = credential.UserName,
            Pass = new string(credential.Password.Reveal()),
        };

        Console.WriteLine($"  Sending: {play}");
        child.StandardInput.WriteLine(DecoderProtocol.Serialize(play));

        Console.Write($"  Waiting up to {seconds}s for Playing ... ");
        var playDeadline = Stopwatch.StartNew();
        var playing = false;

        while (playDeadline.Elapsed < TimeSpan.FromSeconds(seconds))
        {
            lock (states)
            {
                if (states.Contains("Playing"))
                {
                    playing = true;
                    break;
                }
            }

            if (child.HasExited)
            {
                break;
            }

            Thread.Sleep(100);
        }

        Console.WriteLine(playing ? "OK" : "no");

        child.StandardInput.WriteLine(
            DecoderProtocol.Serialize(new DecoderCommand { Op = DecoderCommand.OpQuit }));

        child.WaitForExit(3000);
        child.Kill();

        Console.WriteLine();
        Console.WriteLine("=== Result ===");
        Console.WriteLine($"Integrity applied : {(integrityMatches ? "yes" : "NO")} ({SandboxInspector.Describe(actualSid)})");
        Console.WriteLine($"Window handle     : {(surface != 0 ? "yes" : "no")}");
        Console.WriteLine($"Reached Playing   : {(playing ? "yes" : "no")}");

        lock (states)
        {
            Console.WriteLine($"States seen       : {(states.Count == 0 ? "(none)" : string.Join(", ", states))}");
        }

        DumpErrors(errors);

        Console.WriteLine();

        if (!integrityMatches)
        {
            Console.WriteLine("VERDICT: sandbox did NOT apply the requested integrity level");
            return 7;
        }

        if (!playing)
        {
            Console.WriteLine($"VERDICT: sandbox applied ({SandboxInspector.Describe(actualSid)}) but playback FAILED");
            return 8;
        }

        Console.WriteLine($"VERDICT: OK — playing inside a {SandboxInspector.Describe(actualSid)}-integrity sandbox");
        return 0;
    }

    private static void DumpErrors(List<string> errors)
    {
        lock (errors)
        {
            if (errors.Count == 0)
            {
                return;
            }

            Console.WriteLine();
            Console.WriteLine("=== Decoder diagnostics ===");
            foreach (var line in errors.Take(20))
            {
                Console.WriteLine("  " + line);
            }
        }
    }

    private static string? LocateDecoder(string[] args)
    {
        var explicitPath = ReadString(args, "--decoder", string.Empty);
        if (explicitPath.Length > 0)
        {
            return File.Exists(explicitPath) ? explicitPath : null;
        }

        const string exeName = "TapoViewer.Decoder.exe";
        var baseDir = AppContext.BaseDirectory;

        // Deployed layout: alongside this tool.
        var sibling = Path.Combine(baseDir, exeName);
        if (File.Exists(sibling))
        {
            return sibling;
        }

        // Dev layout: walk up to the repo root and into the decoder's build output.
        var directory = new DirectoryInfo(baseDir);
        while (directory is not null)
        {
            var candidate = Path.Combine(
                directory.FullName,
                "src",
                "TapoViewer.Decoder",
                "bin",
                "Debug",
                "net8.0-windows",
                exeName);

            if (File.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        return null;
    }

    private static string ReadString(string[] args, string name, string fallback)
    {
        var index = Array.IndexOf(args, name);
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : fallback;
    }

    private static int ReadInt(string[] args, string name, int fallback)
        => int.TryParse(ReadString(args, name, string.Empty), out var value) ? value : fallback;
}
