using TapoViewer.Core.Configuration;
using TapoViewer.Core.Onvif;
using TapoViewer.Core.Rtsp;
using TapoViewer.Core.Security;

namespace TapoViewer.Probe;

/// <summary>
/// A read-only diagnostic: proves the camera account works, reports what the camera actually
/// supports, and optionally saves the credentials to Windows Credential Manager.
/// </summary>
/// <remarks>
/// Credentials are read from the console and never accepted as command-line arguments. An
/// argument would be visible to every other process on the machine via the process list, and
/// would land in the shell history file besides.
/// </remarks>
internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        if (Array.IndexOf(args, "--sandbox-test") >= 0)
        {
            try
            {
                return SandboxTest.Run(args);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Sandbox test failed: {ex.GetType().Name}: {ex.Message}");
                return 1;
            }
        }

        Console.WriteLine("Tapo camera probe");
        Console.WriteLine("=================");
        Console.WriteLine();
        Console.WriteLine("Reports what your camera supports. Makes no changes to the camera.");
        Console.WriteLine();

        var host = Prompt("Camera IP address");
        if (string.IsNullOrWhiteSpace(host))
        {
            Console.Error.WriteLine("No address given.");
            return 2;
        }

        var onvifPort = PromptPort("ONVIF port", 2020);
        var rtspPort = PromptPort("RTSP port", RtspTarget.DefaultRtspPort);

        Console.WriteLine();
        Console.WriteLine("Enter the Camera Account credentials from the Tapo app");
        Console.WriteLine("(Device Settings > Advanced Settings > Camera Account).");
        Console.WriteLine("This is NOT your TP-Link cloud login.");
        Console.WriteLine();

        var userName = Prompt("Camera account username");
        if (string.IsNullOrWhiteSpace(userName))
        {
            Console.Error.WriteLine("No username given.");
            return 2;
        }

        using var password = ReadMaskedSecret("Camera account password");
        if (password.Length == 0)
        {
            Console.Error.WriteLine("No password given.");
            return 2;
        }

        Console.WriteLine();

        try
        {
            return await ProbeAsync(host, onvifPort, rtspPort, userName, password).ConfigureAwait(false);
        }
        catch (UntrustedHostException ex)
        {
            Fail("Address rejected", ex.Message);
            return 3;
        }
        catch (OnvifAuthenticationException ex)
        {
            Fail("Authentication failed", ex.Message);
            return 4;
        }
        catch (OnvifException ex)
        {
            Fail("ONVIF error", ex.Message);
            return 5;
        }
    }

    private static async Task<int> ProbeAsync(
        string host,
        int onvifPort,
        int rtspPort,
        string userName,
        Secret password)
    {
        Step($"Validating {host} against the private-network policy");
        var onvifEndpoint = await HostGuard.PinAsync(host, onvifPort).ConfigureAwait(false);
        Good($"allowed, pinned to {onvifEndpoint.Address}");

        using var client = new OnvifClient(onvifEndpoint, userName, password);

        Step("GetCapabilities");
        var capabilities = await client.GetCapabilitiesAsync().ConfigureAwait(false);
        Good("credentials accepted");

        Console.WriteLine();
        Console.WriteLine("  Services advertised by the camera:");
        Report("Media ", capabilities.Media);
        Report("PTZ   ", capabilities.Ptz);
        Report("Events", capabilities.Events);
        Console.WriteLine();

        if (capabilities.Media is null)
        {
            Fail("No media service", "The camera advertises no media service, so no stream can be discovered.");
            return 6;
        }

        Step("GetProfiles");
        var profiles = await client.GetProfilesAsync(capabilities.Media).ConfigureAwait(false);
        Good($"{profiles.Count} profile(s)");
        foreach (var profile in profiles)
        {
            Console.WriteLine($"    - {profile}");
        }

        Console.WriteLine();
        Step("GetStreamUri (high quality)");
        var target = await client
            .GetStreamUriAsync(capabilities.Media, profiles[0].Token, StreamQuality.High)
            .ConfigureAwait(false);
        Good($"{target} (same-device check passed)");

        if (target.Endpoint.Port != rtspPort)
        {
            Console.WriteLine(
                $"    note: camera reports RTSP on port {target.Endpoint.Port}, you entered {rtspPort}.");
        }

        if (capabilities.SupportsPtz)
        {
            Console.WriteLine();
            Step("GetPresets");
            try
            {
                var presets = await client
                    .GetPresetsAsync(capabilities.Ptz!, profiles[0].Token)
                    .ConfigureAwait(false);

                Good($"{presets.Count} preset(s)");
                foreach (var preset in presets)
                {
                    Console.WriteLine($"    - {preset}");
                }
            }
            catch (OnvifException ex)
            {
                Warn($"PTZ service present but GetPresets failed: {ex.Message}");
            }
        }
        else
        {
            Console.WriteLine();
            Warn("No PTZ service. This camera is fixed — pan/tilt controls will stay disabled.");
        }

        if (capabilities.SupportsEvents)
        {
            Console.WriteLine();
            Step("CreatePullPointSubscription");
            try
            {
                var subscription = await client
                    .CreatePullPointSubscriptionAsync(capabilities.Events!, TimeSpan.FromMinutes(1))
                    .ConfigureAwait(false);

                Good($"subscribed until {subscription.ExpiresUtc:HH:mm:ss} UTC");

                Step("PullMessages (5s — wave at the camera)");
                var events = await client
                    .PullMessagesAsync(subscription, TimeSpan.FromSeconds(5))
                    .ConfigureAwait(false);

                Good($"{events.Count} notification(s)");
                foreach (var received in events.Take(5))
                {
                    Console.WriteLine($"    - {received.Topic} motion={received.IsMotionDetected}");
                }

                await client.UnsubscribeAsync(subscription).ConfigureAwait(false);
            }
            catch (OnvifException ex)
            {
                Warn($"Event service present but subscription failed: {ex.Message}");
            }
        }
        else
        {
            Console.WriteLine();
            Warn("No event service. Motion notifications will be unavailable.");
        }

        Console.WriteLine();
        Console.WriteLine("Probe complete.");
        Console.WriteLine();

        OfferToSave(host, rtspPort, onvifPort, userName, password, capabilities);
        return 0;
    }

    private static void OfferToSave(
        string host,
        int rtspPort,
        int onvifPort,
        string userName,
        Secret password,
        OnvifCapabilities capabilities)
    {
        Console.Write("Save this camera and store the password in Windows Credential Manager? [y/N] ");
        var answer = Console.ReadLine();

        if (answer is null || !answer.Trim().StartsWith('y') && !answer.Trim().StartsWith('Y'))
        {
            Console.WriteLine("Nothing saved.");
            return;
        }

        var displayName = Prompt("Display name", "Tapo Camera");
        var id = CameraProfile.NewId();

        var vault = new WindowsCredentialVault();
        vault.Store(id, userName, password.Reveal());

        var store = new CameraConfigStore();
        var existing = store.Load().ToList();
        existing.Add(new CameraProfile
        {
            Id = id,
            DisplayName = displayName,
            Host = host,
            RtspPort = rtspPort,
            OnvifPort = onvifPort,
            MotionEventsEnabled = capabilities.SupportsEvents,
        });

        store.Save(existing);

        Console.WriteLine();
        Good($"password stored under 'TapoViewer:camera:{id}'");
        Good($"camera saved to {store.FilePath} (contains no credentials)");
    }

    // --- console helpers ------------------------------------------------------------------

    private static string Prompt(string label, string? defaultValue = null)
    {
        Console.Write(defaultValue is null ? $"{label}: " : $"{label} [{defaultValue}]: ");
        var value = Console.ReadLine();

        return string.IsNullOrWhiteSpace(value) ? defaultValue ?? string.Empty : value.Trim();
    }

    private static int PromptPort(string label, int defaultValue)
    {
        while (true)
        {
            var raw = Prompt(label, defaultValue.ToString());
            if (int.TryParse(raw, out var port) && port is >= 1 and <= 65535)
            {
                return port;
            }

            Console.Error.WriteLine("  Enter a port between 1 and 65535.");
        }
    }

    /// <summary>Reads a password without echoing it, into a buffer that is zeroed afterwards.</summary>
    private static Secret ReadMaskedSecret(string label)
    {
        Console.Write($"{label}: ");

        var buffer = new char[512];
        var length = 0;

        try
        {
            while (true)
            {
                var key = Console.ReadKey(intercept: true);

                if (key.Key == ConsoleKey.Enter)
                {
                    Console.WriteLine();
                    break;
                }

                if (key.Key == ConsoleKey.Backspace)
                {
                    if (length > 0)
                    {
                        buffer[--length] = '\0';
                        Console.Write("\b \b");
                    }

                    continue;
                }

                if (key.KeyChar == '\0' || char.IsControl(key.KeyChar) || length == buffer.Length)
                {
                    continue;
                }

                buffer[length++] = key.KeyChar;
                Console.Write('*');
            }

            return Secret.FromChars(buffer.AsSpan(0, length));
        }
        finally
        {
            Array.Clear(buffer);
        }
    }

    private static void Step(string message) => Console.Write($"  {message} ... ");

    private static void Good(string message)
    {
        var previous = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"OK  {message}");
        Console.ForegroundColor = previous;
    }

    private static void Warn(string message)
    {
        var previous = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"  !  {message}");
        Console.ForegroundColor = previous;
    }

    private static void Fail(string title, string detail)
    {
        var previous = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine();
        Console.WriteLine($"FAILED: {title}");
        Console.ForegroundColor = previous;
        Console.WriteLine($"  {detail}");
    }

    private static void Report(string label, Uri? uri)
    {
        if (uri is null)
        {
            Console.WriteLine($"    {label} : not supported");
        }
        else
        {
            Console.WriteLine($"    {label} : {uri}");
        }
    }
}
