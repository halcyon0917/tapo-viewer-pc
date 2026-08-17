using System.Text.Json;
using System.Text.Json.Serialization;

namespace TapoViewer.Core.Configuration;

/// <summary>Thrown when the config file on disk is unusable or contains something it should not.</summary>
public sealed class ConfigurationException : Exception
{
    public ConfigurationException(string message) : base(message)
    {
    }

    public ConfigurationException(string message, Exception inner) : base(message, inner)
    {
    }
}

/// <summary>Persists <see cref="CameraProfile"/> records as JSON under %LOCALAPPDATA%.</summary>
public sealed class CameraConfigStore
{
    /// <summary>Property names we refuse to accept in a config file, in any casing.</summary>
    private static readonly string[] ForbiddenKeys =
    [
        "password", "passwd", "pass", "secret", "credential", "credentials", "token", "userinfo",
    ];

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly string _filePath;

    public CameraConfigStore(string? filePath = null)
    {
        _filePath = filePath ?? DefaultFilePath;
    }

    public static string DefaultDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "TapoViewer");

    public static string DefaultFilePath => Path.Combine(DefaultDirectory, "cameras.json");

    public string FilePath => _filePath;

    /// <summary>Previous generation of the config, written on every successful save.</summary>
    public string BackupFilePath => _filePath + ".bak";

    public IReadOnlyList<CameraProfile> Load()
    {
        if (!File.Exists(_filePath))
        {
            return [];
        }

        string json;
        try
        {
            json = File.ReadAllText(_filePath);
        }
        catch (IOException ex)
        {
            throw new ConfigurationException($"Could not read '{_filePath}'.", ex);
        }
        catch (UnauthorizedAccessException ex)
        {
            throw new ConfigurationException($"Access denied reading '{_filePath}'.", ex);
        }

        if (string.IsNullOrWhiteSpace(json))
        {
            return [];
        }

        RejectSecretsInFile(json);

        List<CameraProfile>? profiles;
        try
        {
            profiles = JsonSerializer.Deserialize<List<CameraProfile>>(json, SerializerOptions);
        }
        catch (JsonException ex)
        {
            throw new ConfigurationException($"'{_filePath}' is not valid JSON.", ex);
        }

        if (profiles is null)
        {
            return [];
        }

        foreach (var profile in profiles)
        {
            var error = profile.Validate();
            if (error is not null)
            {
                throw new ConfigurationException(
                    $"Camera '{profile.DisplayName}' in '{_filePath}' is invalid: {error}");
            }
        }

        var duplicate = profiles
            .GroupBy(p => p.Id, StringComparer.Ordinal)
            .FirstOrDefault(g => g.Count() > 1);

        if (duplicate is not null)
        {
            throw new ConfigurationException(
                $"'{_filePath}' contains more than one camera with id '{duplicate.Key}'.");
        }

        return profiles;
    }

    public void Save(IEnumerable<CameraProfile> profiles)
    {
        ArgumentNullException.ThrowIfNull(profiles);

        var list = profiles.ToList();
        foreach (var profile in list)
        {
            var error = profile.Validate();
            if (error is not null)
            {
                throw new ConfigurationException($"Refusing to save an invalid camera: {error}");
            }
        }

        var json = JsonSerializer.Serialize(list, SerializerOptions);

        // Guard the invariant that makes this file safe to hand to anyone. If a future change
        // adds a secret-bearing property to CameraProfile, this throws instead of quietly
        // writing plaintext credentials to disk.
        RejectSecretsInFile(json);

        var directory = Path.GetDirectoryName(_filePath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        // Keep the previous contents before replacing them. The atomic swap below protects
        // against a torn write, but not against a write that is structurally fine and simply
        // wrong — an accidental removal, a mis-click, a bug. Losing a camera means re-running
        // discovery and re-entering a password, so one generation of history is cheap insurance
        // and the file is non-sensitive by construction.
        if (File.Exists(_filePath))
        {
            try
            {
                File.Copy(_filePath, BackupFilePath, overwrite: true);
            }
            catch (IOException)
            {
                // A missing backup must never block saving the real thing.
            }
            catch (UnauthorizedAccessException)
            {
                // Ditto.
            }
        }

        // Write to a sibling temp file and swap, so a crash mid-write cannot leave a truncated
        // config that loses every camera the user configured.
        var temp = _filePath + ".tmp";
        File.WriteAllText(temp, json);
        File.Move(temp, _filePath, overwrite: true);
    }

    /// <summary>
    /// Fails if the JSON carries any property that looks like a secret.
    /// </summary>
    /// <remarks>
    /// Runs on both load and save. On save it protects the invariant above. On load it catches
    /// the user who hand-edits <c>"password": "..."</c> into the file because that is what every
    /// other RTSP tool expects — better to refuse loudly and point them at the vault than to
    /// silently normalise a plaintext password onto their disk.
    /// </remarks>
    private void RejectSecretsInFile(string json)
    {
        using var document = ParseOrThrow(json);

        foreach (var element in EnumerateAll(document.RootElement))
        {
            if (element.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            foreach (var property in element.EnumerateObject())
            {
                foreach (var forbidden in ForbiddenKeys)
                {
                    if (property.Name.Contains(forbidden, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new ConfigurationException(
                            $"'{_filePath}' contains a '{property.Name}' field. This application " +
                            "never stores camera passwords in its configuration — they belong in " +
                            "Windows Credential Manager. Remove the field and enter the password " +
                            "in the app instead.");
                    }
                }
            }
        }
    }

    private JsonDocument ParseOrThrow(string json)
    {
        try
        {
            return JsonDocument.Parse(json);
        }
        catch (JsonException ex)
        {
            throw new ConfigurationException($"'{_filePath}' is not valid JSON.", ex);
        }
    }

    private static IEnumerable<JsonElement> EnumerateAll(JsonElement element)
    {
        yield return element;

        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    foreach (var descendant in EnumerateAll(property.Value))
                    {
                        yield return descendant;
                    }
                }

                break;

            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                {
                    foreach (var descendant in EnumerateAll(item))
                    {
                        yield return descendant;
                    }
                }

                break;
        }
    }
}
