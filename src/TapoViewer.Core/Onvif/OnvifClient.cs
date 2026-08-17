using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using TapoViewer.Core.Rtsp;
using TapoViewer.Core.Security;

namespace TapoViewer.Core.Onvif;

/// <summary>
/// A minimal ONVIF Profile S client: stream discovery, PTZ, and pull-point events.
/// </summary>
/// <remarks>
/// Hand-rolled rather than generated from the ONVIF WSDLs on purpose. The generated stack pulls
/// in a large SOAP surface with its own XML settings, and the whole point of this project is a
/// small, auditable attack surface. We need six operations; that is a few hundred lines of
/// explicit, hardened code versus a dependency nobody will read.
///
/// Every response is parsed with DTD processing prohibited, no entity expansion, and no external
/// resolver — a camera on an untrusted IoT VLAN is exactly the kind of peer that gets to hand us
/// XML, and XXE against our own filesystem would be the obvious payload.
/// </remarks>
public sealed class OnvifClient : IDisposable
{
    private const int MaxResponseBytes = 1 * 1024 * 1024;

    private static readonly XNamespace Soap = "http://www.w3.org/2003/05/soap-envelope";
    private static readonly XNamespace Wsse = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private static readonly XNamespace Wsu = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    private static readonly XNamespace Wsa = "http://www.w3.org/2005/08/addressing";
    private static readonly XNamespace Device = "http://www.onvif.org/ver10/device/wsdl";
    private static readonly XNamespace Media = "http://www.onvif.org/ver10/media/wsdl";
    private static readonly XNamespace Ptz = "http://www.onvif.org/ver20/ptz/wsdl";
    private static readonly XNamespace Events = "http://www.onvif.org/ver10/events/wsdl";
    private static readonly XNamespace Schema = "http://www.onvif.org/ver10/schema";

    private const string PasswordDigestType =
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest";

    private const string Base64BinaryType =
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";

    /// <summary>
    /// Hardened reader settings. <see cref="DtdProcessing.Prohibit"/> plus a null resolver is
    /// what closes XXE and billion-laughs; both are required by CA3075, which this build treats
    /// as an error.
    /// </summary>
    private static readonly XmlReaderSettings ReaderSettings = new()
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        MaxCharactersFromEntities = 0,
        IgnoreComments = true,
        IgnoreProcessingInstructions = true,
        CloseInput = true,
    };

    private readonly HttpClient _http;
    private readonly PinnedEndpoint _device;
    private readonly string _userName;
    private readonly Secret _password;
    private readonly bool _ownsHttpClient;

    public OnvifClient(
        PinnedEndpoint device,
        string userName,
        Secret password,
        HttpClient? httpClient = null)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentException.ThrowIfNullOrEmpty(userName);
        ArgumentNullException.ThrowIfNull(password);

        _device = device;
        _userName = userName;
        _password = password;

        _ownsHttpClient = httpClient is null;
        _http = httpClient ?? new HttpClient(new SocketsHttpHandler
        {
            // No redirects: an ONVIF service has no legitimate reason to bounce us elsewhere,
            // and following one would defeat the same-device check.
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromSeconds(5),
        })
        {
            // Deliberately unbounded at the client level; every call is bounded individually
            // instead. A single client-wide timeout cannot serve both ordinary requests, which
            // should fail fast, and PullMessages, which is a long poll the camera is *supposed*
            // to hold open until either an event arrives or the pull timeout expires.
            Timeout = Timeout.InfiniteTimeSpan,
        };
    }

    /// <summary>Bound for ordinary request/response operations.</summary>
    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromSeconds(15);

    /// <summary>The device service endpoint, derived from the pinned address.</summary>
    public Uri DeviceServiceUri => new($"http://{_device.UriHost}:{_device.Port}/onvif/device_service");

    // --- Capabilities and profiles -------------------------------------------------------

    public async Task<OnvifCapabilities> GetCapabilitiesAsync(CancellationToken cancellationToken = default)
    {
        var body = new XElement(Device + "GetCapabilities",
            new XElement(Device + "Category", "All"));

        var response = await InvokeAsync(DeviceServiceUri, body, cancellationToken).ConfigureAwait(false);

        var capabilities = response.Descendants(Device + "Capabilities").FirstOrDefault()
            ?? response.Descendants(Schema + "Capabilities").FirstOrDefault()
            ?? throw new OnvifException("Device did not return a Capabilities element.");

        return new OnvifCapabilities(
            ReadServiceUri(capabilities, "Media"),
            ReadServiceUri(capabilities, "PTZ"),
            ReadServiceUri(capabilities, "Events"));
    }

    public async Task<IReadOnlyList<OnvifProfile>> GetProfilesAsync(
        Uri mediaService,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(mediaService);

        var response = await InvokeAsync(mediaService, new XElement(Media + "GetProfiles"), cancellationToken)
            .ConfigureAwait(false);

        var profiles = new List<OnvifProfile>();
        foreach (var element in response.Descendants(Media + "Profiles"))
        {
            var token = (string?)element.Attribute("token");
            if (string.IsNullOrEmpty(token))
            {
                continue;
            }

            var name = element.Element(Schema + "Name")?.Value ?? token;
            profiles.Add(new OnvifProfile(token, name));
        }

        if (profiles.Count == 0)
        {
            throw new OnvifException("Device returned no media profiles.");
        }

        return profiles;
    }

    /// <summary>
    /// Asks the device where its stream lives, then refuses to believe it unless the answer
    /// points back at the device.
    /// </summary>
    public async Task<RtspTarget> GetStreamUriAsync(
        Uri mediaService,
        string profileToken,
        StreamQuality quality,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(mediaService);
        ArgumentException.ThrowIfNullOrEmpty(profileToken);

        var body = new XElement(Media + "GetStreamUri",
            new XElement(Media + "StreamSetup",
                new XElement(Schema + "Stream", "RTP-Unicast"),
                new XElement(Schema + "Transport",
                    new XElement(Schema + "Protocol", "RTSP"))),
            new XElement(Media + "ProfileToken", profileToken));

        var response = await InvokeAsync(mediaService, body, cancellationToken).ConfigureAwait(false);

        var raw = response.Descendants(Schema + "Uri").FirstOrDefault()?.Value
            ?? response.Descendants(Media + "Uri").FirstOrDefault()?.Value
            ?? throw new OnvifException("Device did not return a stream URI.");

        if (!Uri.TryCreate(raw, UriKind.Absolute, out var streamUri))
        {
            throw new OnvifException($"Device returned an unparseable stream URI: '{raw}'.");
        }

        // The security-critical step. See HostGuard.EnsureSameDevice.
        var endpoint = HostGuard.EnsureSameDevice(_device, streamUri, HostGuard.RtspSchemes);

        return new RtspTarget(endpoint, quality);
    }

    // --- PTZ -----------------------------------------------------------------------------

    public async Task ContinuousMoveAsync(
        Uri ptzService,
        string profileToken,
        PtzVelocity velocity,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ptzService);
        ArgumentException.ThrowIfNullOrEmpty(profileToken);

        var body = new XElement(Ptz + "ContinuousMove",
            new XElement(Ptz + "ProfileToken", profileToken),
            new XElement(Ptz + "Velocity",
                new XElement(Schema + "PanTilt",
                    new XAttribute("x", Format(velocity.Pan)),
                    new XAttribute("y", Format(velocity.Tilt))),
                new XElement(Schema + "Zoom",
                    new XAttribute("x", Format(velocity.Zoom)))));

        await InvokeAsync(ptzService, body, cancellationToken).ConfigureAwait(false);
    }

    public async Task StopAsync(
        Uri ptzService,
        string profileToken,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ptzService);
        ArgumentException.ThrowIfNullOrEmpty(profileToken);

        var body = new XElement(Ptz + "Stop",
            new XElement(Ptz + "ProfileToken", profileToken),
            new XElement(Ptz + "PanTilt", true),
            new XElement(Ptz + "Zoom", true));

        await InvokeAsync(ptzService, body, cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<OnvifPreset>> GetPresetsAsync(
        Uri ptzService,
        string profileToken,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ptzService);
        ArgumentException.ThrowIfNullOrEmpty(profileToken);

        var body = new XElement(Ptz + "GetPresets",
            new XElement(Ptz + "ProfileToken", profileToken));

        var response = await InvokeAsync(ptzService, body, cancellationToken).ConfigureAwait(false);

        var presets = new List<OnvifPreset>();
        foreach (var element in response.Descendants(Ptz + "Preset"))
        {
            var token = (string?)element.Attribute("token");
            if (string.IsNullOrEmpty(token))
            {
                continue;
            }

            presets.Add(new OnvifPreset(token, element.Element(Schema + "Name")?.Value ?? token));
        }

        return presets;
    }

    public async Task GotoPresetAsync(
        Uri ptzService,
        string profileToken,
        string presetToken,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ptzService);
        ArgumentException.ThrowIfNullOrEmpty(profileToken);
        ArgumentException.ThrowIfNullOrEmpty(presetToken);

        var body = new XElement(Ptz + "GotoPreset",
            new XElement(Ptz + "ProfileToken", profileToken),
            new XElement(Ptz + "PresetToken", presetToken));

        await InvokeAsync(ptzService, body, cancellationToken).ConfigureAwait(false);
    }

    public async Task<string> SetPresetAsync(
        Uri ptzService,
        string profileToken,
        string presetName,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ptzService);
        ArgumentException.ThrowIfNullOrEmpty(profileToken);
        ArgumentException.ThrowIfNullOrEmpty(presetName);

        var body = new XElement(Ptz + "SetPreset",
            new XElement(Ptz + "ProfileToken", profileToken),
            new XElement(Ptz + "PresetName", presetName));

        var response = await InvokeAsync(ptzService, body, cancellationToken).ConfigureAwait(false);

        return response.Descendants(Ptz + "PresetToken").FirstOrDefault()?.Value
            ?? throw new OnvifException("Device did not return a preset token.");
    }

    // --- Events ---------------------------------------------------------------------------

    /// <summary>Creates a pull-point subscription for motion notifications.</summary>
    /// <remarks>
    /// Pull-point, not base subscription: base subscriptions require the camera to POST back to
    /// <i>us</i>, which means running a listening HTTP server in this process for an IoT device
    /// to talk to. Pulling keeps every connection outbound and leaves no inbound surface.
    /// </remarks>
    public async Task<OnvifSubscription> CreatePullPointSubscriptionAsync(
        Uri eventService,
        TimeSpan initialTermination,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(eventService);

        var body = new XElement(Events + "CreatePullPointSubscription",
            new XElement(Events + "InitialTerminationTime", ToDuration(initialTermination)));

        var response = await InvokeAsync(eventService, body, cancellationToken).ConfigureAwait(false);

        var address = response.Descendants(Events + "SubscriptionReference")
            .Descendants(Wsa + "Address").FirstOrDefault()?.Value
            ?? throw new OnvifException("Device did not return a subscription reference.");

        if (!Uri.TryCreate(address, UriKind.Absolute, out var endpoint))
        {
            throw new OnvifException($"Device returned an unparseable subscription address: '{address}'.");
        }

        // Same rule as stream URIs: the pull endpoint must be on the device itself.
        var pinned = HostGuard.EnsureSameDevice(_device, endpoint, HostGuard.OnvifSchemes);
        var safeEndpoint = new UriBuilder(endpoint) { Host = pinned.Address.ToString(), Port = pinned.Port }.Uri;

        var expires = ParseTermination(response) ?? DateTimeOffset.UtcNow.Add(initialTermination);

        return new OnvifSubscription(safeEndpoint, expires);
    }

    /// <summary>Pulls pending notifications. Returns an empty list when nothing happened.</summary>
    public async Task<IReadOnlyList<OnvifEvent>> PullMessagesAsync(
        OnvifSubscription subscription,
        TimeSpan timeout,
        int maxMessages = 32,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(subscription);

        var body = new XElement(Events + "PullMessages",
            new XElement(Events + "Timeout", ToDuration(timeout)),
            new XElement(Events + "MessageLimit", maxMessages));

        // Allow the camera the full pull window plus transport margin. Aborting earlier than the
        // timeout we just asked it to honour would guarantee failure on every quiet interval.
        var response = await InvokeAsync(
            subscription.Endpoint,
            body,
            cancellationToken,
            timeout: timeout + TimeSpan.FromSeconds(10)).ConfigureAwait(false);

        var events = new List<OnvifEvent>();
        var now = DateTimeOffset.UtcNow;

        foreach (var notification in response.Descendants().Where(e => e.Name.LocalName == "NotificationMessage"))
        {
            var topic = notification.Descendants().FirstOrDefault(e => e.Name.LocalName == "Topic")?.Value?.Trim()
                ?? string.Empty;

            // ONVIF encodes the actual state in SimpleItem name/value pairs, e.g.
            // <tt:SimpleItem Name="IsMotion" Value="true"/>. Names vary between vendors, so
            // match on the value of any motion-ish item rather than a single hard-coded name.
            var motion = false;
            foreach (var item in notification.Descendants().Where(e => e.Name.LocalName == "SimpleItem"))
            {
                var name = (string?)item.Attribute("Name") ?? string.Empty;
                var value = (string?)item.Attribute("Value") ?? string.Empty;

                if (name.Contains("motion", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("IsMotion", StringComparison.OrdinalIgnoreCase) ||
                    topic.Contains("Motion", StringComparison.OrdinalIgnoreCase))
                {
                    if (bool.TryParse(value, out var parsed) && parsed)
                    {
                        motion = true;
                    }
                }
            }

            events.Add(new OnvifEvent(topic, motion, now));
        }

        return events;
    }

    public async Task RenewAsync(
        OnvifSubscription subscription,
        TimeSpan termination,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(subscription);

        var body = new XElement(Events + "Renew",
            new XElement(Events + "TerminationTime", ToDuration(termination)));

        await InvokeAsync(subscription.Endpoint, body, cancellationToken).ConfigureAwait(false);
    }

    public async Task UnsubscribeAsync(
        OnvifSubscription subscription,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(subscription);

        await InvokeAsync(subscription.Endpoint, new XElement(Events + "Unsubscribe"), cancellationToken)
            .ConfigureAwait(false);
    }

    // --- Transport ------------------------------------------------------------------------

    private async Task<XElement> InvokeAsync(
        Uri endpoint,
        XElement body,
        CancellationToken cancellationToken,
        TimeSpan? timeout = null)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout ?? RequestTimeout);
        var callToken = deadline.Token;

        var envelope = new XDocument(
            new XElement(Soap + "Envelope",
                new XAttribute(XNamespace.Xmlns + "s", Soap.NamespaceName),
                new XElement(Soap + "Header", BuildSecurityHeader()),
                new XElement(Soap + "Body", body)));

        using var content = new StringContent(
            envelope.ToString(SaveOptions.DisableFormatting),
            Encoding.UTF8);

        content.Headers.ContentType = new MediaTypeHeaderValue("application/soap+xml")
        {
            CharSet = "utf-8",
        };

        HttpResponseMessage response;
        try
        {
            response = await _http.PostAsync(endpoint, content, callToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw new OnvifException($"Could not reach the ONVIF service at {endpoint}.", ex);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            // Our per-call deadline fired, not the caller's cancellation.
            throw new OnvifException($"The ONVIF service at {endpoint} timed out.", ex);
        }

        using (response)
        {
            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                throw new OnvifAuthenticationException(
                    "The camera rejected the Camera Account credentials. Check the username and " +
                    "password set under Device Settings > Advanced Settings > Camera Account in " +
                    "the Tapo app. Note the camera also rejects requests when its clock is more " +
                    "than a few seconds out of sync.");
            }

            var payload = await ReadCappedAsync(response, callToken).ConfigureAwait(false);
            var document = ParseHardened(payload, endpoint);

            var fault = document.Descendants(Soap + "Fault").FirstOrDefault();
            if (fault is not null)
            {
                var reason = fault.Descendants(Soap + "Text").FirstOrDefault()?.Value
                    ?? fault.Descendants().FirstOrDefault(e => e.Name.LocalName == "Text")?.Value
                    ?? fault.Value;

                if (reason.Contains("NotAuthorized", StringComparison.OrdinalIgnoreCase) ||
                    reason.Contains("authoriz", StringComparison.OrdinalIgnoreCase))
                {
                    throw new OnvifAuthenticationException(
                        $"The camera refused the request as unauthorized: {reason.Trim()}");
                }

                throw new OnvifException($"The camera returned a SOAP fault: {reason.Trim()}");
            }

            if (!response.IsSuccessStatusCode)
            {
                throw new OnvifException(
                    $"The ONVIF service returned {(int)response.StatusCode} {response.ReasonPhrase}.");
            }

            return document.Root?.Element(Soap + "Body")
                ?? throw new OnvifException("The ONVIF response had no SOAP body.");
        }
    }

    /// <summary>
    /// Reads the response with a hard byte ceiling.
    /// </summary>
    /// <remarks>
    /// A camera is an untrusted peer that controls its own response length. Without a cap, a
    /// hostile or malfunctioning device can stream indefinitely into our heap and take the app
    /// down — a denial of service that costs the attacker nothing.
    /// </remarks>
    private static async Task<byte[]> ReadCappedAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength is > MaxResponseBytes)
        {
            throw new OnvifException("The ONVIF response exceeded the size limit.");
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var buffer = new MemoryStream();

        var chunk = new byte[8192];
        int read;
        while ((read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + read > MaxResponseBytes)
            {
                throw new OnvifException("The ONVIF response exceeded the size limit.");
            }

            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }

    private static XDocument ParseHardened(byte[] payload, Uri endpoint)
    {
        try
        {
            using var stream = new MemoryStream(payload, writable: false);
            using var reader = XmlReader.Create(stream, ReaderSettings);
            return XDocument.Load(reader);
        }
        catch (XmlException ex)
        {
            throw new OnvifException($"The ONVIF service at {endpoint} returned malformed XML.", ex);
        }
    }

    /// <summary>
    /// Builds a WS-Security UsernameToken header with a digested password.
    /// </summary>
    /// <remarks>
    /// The digest is <c>Base64(SHA1(nonce || created || password))</c>. SHA-1 is weak and this
    /// build fails on CA5350 for exactly that reason — but the algorithm is fixed by the
    /// WS-Security UsernameToken profile that ONVIF mandates, so it is the camera's protocol, not
    /// our choice. It is still meaningfully better than the alternative the spec also allows
    /// (PasswordText, i.e. the password in cleartext), and the nonce plus timestamp gives replay
    /// resistance. The password never travels in recoverable form.
    /// </remarks>
    private XElement BuildSecurityHeader()
    {
        Span<byte> nonce = stackalloc byte[16];
        RandomNumberGenerator.Fill(nonce);

        var created = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
        var createdBytes = Encoding.UTF8.GetBytes(created);

        var password = _password.Reveal();
        var passwordBytes = new byte[Encoding.UTF8.GetByteCount(password)];

        try
        {
            Encoding.UTF8.GetBytes(password, passwordBytes);

            var material = new byte[nonce.Length + createdBytes.Length + passwordBytes.Length];
            try
            {
                nonce.CopyTo(material);
                createdBytes.CopyTo(material.AsSpan(nonce.Length));
                passwordBytes.CopyTo(material.AsSpan(nonce.Length + createdBytes.Length));

#pragma warning disable CA5350 // SHA-1 is mandated by the WS-Security UsernameToken profile.
                var digest = SHA1.HashData(material);
#pragma warning restore CA5350

                return new XElement(Wsse + "Security",
                    new XAttribute(XNamespace.Xmlns + "wsse", Wsse.NamespaceName),
                    new XAttribute(XNamespace.Xmlns + "wsu", Wsu.NamespaceName),
                    new XElement(Wsse + "UsernameToken",
                        new XElement(Wsse + "Username", _userName),
                        new XElement(Wsse + "Password",
                            new XAttribute("Type", PasswordDigestType),
                            Convert.ToBase64String(digest)),
                        new XElement(Wsse + "Nonce",
                            new XAttribute("EncodingType", Base64BinaryType),
                            Convert.ToBase64String(nonce)),
                        new XElement(Wsu + "Created", created)));
            }
            finally
            {
                // The concatenated material contains the plaintext password.
                CryptographicOperations.ZeroMemory(material);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    private Uri? ReadServiceUri(XElement capabilities, string localName)
    {
        var section = capabilities.Elements()
            .FirstOrDefault(e => string.Equals(e.Name.LocalName, localName, StringComparison.OrdinalIgnoreCase));

        var raw = section?.Elements()
            .FirstOrDefault(e => e.Name.LocalName is "XAddr")?.Value;

        if (string.IsNullOrWhiteSpace(raw) || !Uri.TryCreate(raw, UriKind.Absolute, out var uri))
        {
            return null;
        }

        // A device advertising its own service addresses is still a device telling us where to
        // send authenticated requests. Force each one back onto the pinned address.
        var pinned = HostGuard.EnsureSameDevice(_device, uri, HostGuard.OnvifSchemes);

        return new UriBuilder(uri)
        {
            Host = pinned.Address.ToString(),
            Port = pinned.Port,
        }.Uri;
    }

    private static DateTimeOffset? ParseTermination(XElement body)
    {
        var raw = body.Descendants().FirstOrDefault(e => e.Name.LocalName == "TerminationTime")?.Value;

        return DateTimeOffset.TryParse(
            raw,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AdjustToUniversal,
            out var parsed)
            ? parsed
            : null;
    }

    private static string Format(double value) => value.ToString("0.###", CultureInfo.InvariantCulture);

    /// <summary>Formats an xs:duration, which is what ONVIF timeouts expect.</summary>
    private static string ToDuration(TimeSpan value)
    {
        var total = (int)Math.Max(value.TotalSeconds, 1);
        return $"PT{total.ToString(CultureInfo.InvariantCulture)}S";
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _http.Dispose();
        }
    }
}
