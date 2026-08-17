using System.Text.Json;
using System.Text.Json.Serialization;

namespace TapoViewer.Core.Decoding;

/// <summary>Commands the UI sends to a decoder process, one JSON object per line.</summary>
/// <remarks>
/// Travels over the child's inherited stdin, which is why credentials can live in it: an
/// inherited pipe is private to the two processes, unlike a command line (readable by every
/// local user) or an environment block (readable by anything that can open the process).
/// </remarks>
public sealed record DecoderCommand
{
    [JsonPropertyName("op")]
    public required string Op { get; init; }

    [JsonPropertyName("host")]
    public string? Host { get; init; }

    [JsonPropertyName("port")]
    public int Port { get; init; }

    [JsonPropertyName("path")]
    public string? Path { get; init; }

    [JsonPropertyName("user")]
    public string? User { get; init; }

    /// <summary>Camera-account password. Only ever present on an <c>play</c> command.</summary>
    [JsonPropertyName("pass")]
    public string? Pass { get; init; }

    [JsonPropertyName("parentHwnd")]
    public long ParentHwnd { get; init; }

    [JsonPropertyName("x")]
    public int X { get; init; }

    [JsonPropertyName("y")]
    public int Y { get; init; }

    [JsonPropertyName("w")]
    public int Width { get; init; }

    [JsonPropertyName("h")]
    public int Height { get; init; }

    public const string OpPlay = "play";
    public const string OpStop = "stop";
    public const string OpResize = "resize";
    public const string OpQuit = "quit";

    /// <summary>A redacted form safe to log. Never log the object itself.</summary>
    public override string ToString() =>
        $"DecoderCommand {{ Op = {Op}, Host = {Host}, Port = {Port}, Path = {Path}, " +
        $"User = {(string.IsNullOrEmpty(User) ? "(none)" : "(set)")}, " +
        $"Pass = {(string.IsNullOrEmpty(Pass) ? "(none)" : "(redacted)")} }}";
}

/// <summary>Notifications a decoder process sends back over its stdout.</summary>
public sealed record DecoderEvent
{
    [JsonPropertyName("event")]
    public required string Event { get; init; }

    /// <summary>The child's window handle, sent with <c>ready</c>.</summary>
    [JsonPropertyName("hwnd")]
    public long Hwnd { get; init; }

    [JsonPropertyName("value")]
    public string? Value { get; init; }

    [JsonPropertyName("message")]
    public string? Message { get; init; }

    [JsonPropertyName("frames")]
    public long Frames { get; init; }

    public const string EventReady = "ready";
    public const string EventState = "state";
    public const string EventError = "error";
    public const string EventStats = "stats";
}

/// <summary>Newline-delimited JSON framing shared by both sides.</summary>
public static class DecoderProtocol
{
    /// <summary>Refuse absurd lines rather than buffering them; the peer may be misbehaving.</summary>
    public const int MaxLineLength = 8 * 1024;

    private static readonly JsonSerializerOptions Options = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static string Serialize(DecoderCommand command) => JsonSerializer.Serialize(command, Options);

    public static string Serialize(DecoderEvent value) => JsonSerializer.Serialize(value, Options);

    public static DecoderCommand? ParseCommand(string line) => Parse<DecoderCommand>(line);

    public static DecoderEvent? ParseEvent(string line) => Parse<DecoderEvent>(line);

    private static T? Parse<T>(string line) where T : class
    {
        if (string.IsNullOrWhiteSpace(line) || line.Length > MaxLineLength)
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<T>(line, Options);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
