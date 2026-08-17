using System.Globalization;
using LibVLCSharp.Shared;
using TapoViewer.Core.Configuration;
using TapoViewer.Core.Rtsp;
using TapoViewer.Core.Security;

namespace TapoViewer.Decoder;

/// <summary>
/// Plays a configured camera headlessly and reports what happened.
/// </summary>
/// <remarks>
/// Exists to answer two questions that cannot be settled by reading code: does libVLC actually
/// negotiate and decode this camera's RTSP stream, and — since the camera offers Basic ahead of
/// Digest — which authentication scheme does libVLC choose? The second matters because Basic
/// hands over a base64-encoded password.
/// </remarks>
internal static class SelfTest
{
    internal static int Run(string[] args)
    {
        var seconds = ReadInt(args, "--seconds", 8);
        var quality = ReadString(args, "--quality", "high").Equals("standard", StringComparison.OrdinalIgnoreCase)
            ? StreamQuality.Standard
            : StreamQuality.High;

        var store = new CameraConfigStore();
        var cameras = store.Load();
        if (cameras.Count == 0)
        {
            Console.Error.WriteLine($"No cameras configured in {store.FilePath}. Run the probe tool first.");
            return 2;
        }

        var camera = cameras[0];
        Console.WriteLine($"Camera   : {camera.DisplayName} ({camera.Host}:{camera.RtspPort})");
        Console.WriteLine($"Quality  : {quality}");

        var vault = new WindowsCredentialVault();
        using var credential = vault.Retrieve(camera.Id);
        if (credential is null)
        {
            Console.Error.WriteLine($"No stored credential for camera id '{camera.Id}'. Run the probe tool.");
            return 3;
        }

        Console.WriteLine($"Account  : {credential.UserName}");

        var endpoint = HostGuard.Pin(camera.Host, camera.RtspPort);
        var target = new RtspTarget(endpoint, quality);
        Console.WriteLine($"Target   : {target}");
        Console.WriteLine();

        return Play(target, credential, seconds);
    }

    private static int Play(RtspTarget target, CameraCredential credential, int seconds)
    {
        // Fully qualified: our own TapoViewer.Core namespace shadows LibVLCSharp's Core here.
        LibVLCSharp.Shared.Core.Initialize();

        // --vout=dummy: decode fully but render nowhere, so this can run without a window.
        // --verbose=2 surfaces the RTSP handshake, which is the whole point of the exercise.
        using var libvlc = new LibVLC(
            "--intf=dummy",
            "--vout=dummy",
            "--aout=dummy",
            "--no-plugins-cache",
            "--verbose=2");

        var authLines = new List<string>();
        var errorLines = new List<string>();

        libvlc.Log += (_, e) =>
        {
            var message = e.Message ?? string.Empty;

            if (message.Contains("auth", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("Digest", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("Basic", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("401", StringComparison.Ordinal) ||
                message.Contains("Unauthorized", StringComparison.OrdinalIgnoreCase))
            {
                authLines.Add($"[{e.Module}] {message}");
            }

            if (e.Level == LogLevel.Error)
            {
                errorLines.Add($"[{e.Module}] {message}");
            }
        };

        // Credentials are delivered through libVLC's login dialog callback rather than in the
        // URI. This is the only mechanism libVLC offers that keeps them out of the URL string
        // (and therefore out of its own logs and any crash dump of the URL).
        //
        // Caveat worth stating plainly: PostLogin takes System.String, so the password does
        // become a managed string here. That is a limitation of the LibVLCSharp API, not a
        // choice — this is the narrowest exposure available short of patching libVLC.
        var loginAttempts = 0;
        libvlc.SetDialogHandlers(
            error: (_, _) => Task.CompletedTask,
            login: (dialog, _, _, defaultUsername, _, _) =>
            {
                loginAttempts++;
                dialog?.PostLogin(
                    string.IsNullOrEmpty(credential.UserName) ? defaultUsername : credential.UserName,
                    new string(credential.Password.Reveal()),
                    store: false);
                return Task.CompletedTask;
            },
            question: (dialog, _, _, _, _, _, _, _) =>
            {
                dialog?.Dismiss();
                return Task.CompletedTask;
            },
            displayProgress: (_, _, _, _, _, _, _) => Task.CompletedTask,
            updateProgress: (_, _, _) => Task.CompletedTask);

        using var media = new Media(libvlc, target.ToUri());

        // Force RTSP interleaved over TCP. UDP needs the camera to reach back to an ephemeral
        // port on this host, which is both less reliable behind a firewall and more inbound
        // surface than we want from an IoT device.
        media.AddOption(":rtsp-tcp");
        media.AddOption(":network-caching=300");

        using var player = new MediaPlayer(libvlc);

        var playing = false;
        var encounteredError = false;

        player.Playing += (_, _) => playing = true;
        player.EncounteredError += (_, _) => encounteredError = true;

        Console.WriteLine("Connecting ...");
        if (!player.Play(media))
        {
            Console.Error.WriteLine("libVLC refused to start playback.");
            return 4;
        }

        var deadline = DateTime.UtcNow.AddSeconds(seconds);
        while (DateTime.UtcNow < deadline && !encounteredError)
        {
            Thread.Sleep(200);
        }

        var report = Describe(player, media, playing, encounteredError, loginAttempts, authLines, errorLines);

        player.Stop();

        return report;
    }

    private static int Describe(
        MediaPlayer player,
        Media media,
        bool playing,
        bool encounteredError,
        int loginAttempts,
        List<string> authLines,
        List<string> errorLines)
    {
        Console.WriteLine();
        Console.WriteLine("=== Result ===");
        Console.WriteLine($"Playing        : {playing}");
        Console.WriteLine($"State          : {player.State}");
        Console.WriteLine($"Login callbacks: {loginAttempts}");

        var videoTrack = media.Tracks.FirstOrDefault(t => t.TrackType == TrackType.Video);
        if (videoTrack.TrackType == TrackType.Video)
        {
            var video = videoTrack.Data.Video;
            Console.WriteLine(
                $"Video track    : {video.Width}x{video.Height} codec={FourCc(videoTrack.Codec)}");
        }
        else
        {
            Console.WriteLine("Video track    : none reported");
        }

        var stats = media.Statistics;
        Console.WriteLine($"Decoded frames : {stats.DecodedVideo}");
        Console.WriteLine($"Demux bytes    : {stats.DemuxReadBytes}");
        Console.WriteLine($"Dropped frames : {stats.LostPictures}");

        Console.WriteLine();
        Console.WriteLine("=== Authentication trace ===");
        if (authLines.Count == 0)
        {
            Console.WriteLine("(libVLC logged nothing matching auth/Basic/Digest/401)");
        }
        else
        {
            foreach (var line in authLines.Take(25))
            {
                Console.WriteLine("  " + line);
            }
        }

        if (errorLines.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine("=== Errors ===");
            foreach (var line in errorLines.Take(15))
            {
                Console.WriteLine("  " + line);
            }
        }

        Console.WriteLine();

        if (encounteredError || !playing)
        {
            Console.WriteLine("VERDICT: playback FAILED");
            return 5;
        }

        if (stats.DecodedVideo == 0)
        {
            Console.WriteLine("VERDICT: connected but decoded no video frames");
            return 6;
        }

        Console.WriteLine("VERDICT: playback OK");
        return 0;
    }

    private static string FourCc(uint codec)
    {
        Span<char> chars =
        [
            (char)(codec & 0xFF),
            (char)((codec >> 8) & 0xFF),
            (char)((codec >> 16) & 0xFF),
            (char)((codec >> 24) & 0xFF),
        ];

        foreach (var c in chars)
        {
            if (char.IsControl(c))
            {
                return codec.ToString(CultureInfo.InvariantCulture);
            }
        }

        return new string(chars).Trim();
    }

    private static string ReadString(string[] args, string name, string fallback)
    {
        var index = Array.IndexOf(args, name);
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : fallback;
    }

    private static int ReadInt(string[] args, string name, int fallback)
        => int.TryParse(ReadString(args, name, string.Empty), out var value) ? value : fallback;
}
