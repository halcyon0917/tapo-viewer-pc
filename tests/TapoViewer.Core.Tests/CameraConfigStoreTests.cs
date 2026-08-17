using TapoViewer.Core.Configuration;
using TapoViewer.Core.Rtsp;

namespace TapoViewer.Core.Tests;

public sealed class CameraConfigStoreTests : IDisposable
{
    private readonly string _directory;
    private readonly CameraConfigStore _store;

    public CameraConfigStoreTests()
    {
        _directory = Path.Combine(Path.GetTempPath(), "TapoViewerTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_directory);
        _store = new CameraConfigStore(Path.Combine(_directory, "cameras.json"));
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    private static CameraProfile Sample(string id = "cam-1", string host = "192.168.1.50") => new()
    {
        Id = id,
        DisplayName = "Front Door",
        Host = host,
    };

    [Fact]
    public void Load_returns_empty_when_no_file_exists()
    {
        Assert.Empty(_store.Load());
    }

    [Fact]
    public void Round_trips_a_profile_with_defaults()
    {
        _store.Save([Sample()]);

        var loaded = _store.Load();

        var profile = Assert.Single(loaded);
        Assert.Equal("cam-1", profile.Id);
        Assert.Equal("Front Door", profile.DisplayName);
        Assert.Equal("192.168.1.50", profile.Host);
        Assert.Equal(554, profile.RtspPort);
        Assert.Equal(2020, profile.OnvifPort);
        Assert.Equal(StreamQuality.High, profile.PreferredQuality);
        Assert.False(profile.MotionEventsEnabled);
    }

    [Fact]
    public void Round_trips_multiple_profiles_and_non_default_values()
    {
        CameraProfile[] input =
        [
            Sample("cam-1") with { PreferredQuality = StreamQuality.Standard, MotionEventsEnabled = true },
            Sample("cam-2", "10.0.0.7") with { RtspPort = 5540, OnvifPort = 8080 },
        ];

        _store.Save(input);

        Assert.Equal(input, _store.Load());
    }

    [Fact]
    public void Written_file_contains_no_credential_fields()
    {
        _store.Save([Sample()]);

        var json = File.ReadAllText(_store.FilePath);

        Assert.DoesNotContain("password", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("secret", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("user", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Enum_is_written_as_a_name_not_a_number()
    {
        // Numeric enums make the file unreadable and silently shift meaning if the enum is
        // ever reordered.
        _store.Save([Sample() with { PreferredQuality = StreamQuality.Standard }]);

        Assert.Contains("\"Standard\"", File.ReadAllText(_store.FilePath), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("password")]
    [InlineData("Password")]
    [InlineData("cameraPassword")]
    [InlineData("secret")]
    [InlineData("token")]
    public void Load_refuses_a_hand_edited_file_containing_a_secret(string key)
    {
        File.WriteAllText(
            _store.FilePath,
            $$"""[{"Id":"cam-1","DisplayName":"Front Door","Host":"192.168.1.50","{{key}}":"hunter2"}]""");

        var ex = Assert.Throws<ConfigurationException>(() => _store.Load());
        Assert.Contains("Credential Manager", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Load_rejects_malformed_json()
    {
        File.WriteAllText(_store.FilePath, "{ not json");

        Assert.Throws<ConfigurationException>(() => _store.Load());
    }

    [Fact]
    public void Load_rejects_duplicate_camera_ids()
    {
        File.WriteAllText(
            _store.FilePath,
            """
            [{"Id":"cam-1","DisplayName":"A","Host":"192.168.1.50"},
             {"Id":"cam-1","DisplayName":"B","Host":"192.168.1.51"}]
            """);

        var ex = Assert.Throws<ConfigurationException>(() => _store.Load());
        Assert.Contains("cam-1", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Load_rejects_an_invalid_profile()
    {
        File.WriteAllText(
            _store.FilePath,
            """[{"Id":"cam-1","DisplayName":"A","Host":"192.168.1.50","RtspPort":0}]""");

        Assert.Throws<ConfigurationException>(() => _store.Load());
    }

    [Fact]
    public void Save_refuses_an_invalid_profile()
    {
        var bad = Sample() with { Id = "has space" };

        Assert.Throws<ConfigurationException>(() => _store.Save([bad]));
    }

    [Fact]
    public void Save_keeps_the_previous_generation_as_a_backup()
    {
        _store.Save([Sample("cam-1"), Sample("cam-2", "10.0.0.7")]);

        // Simulate the destructive case this exists for: everything removed.
        _store.Save([]);

        Assert.Empty(_store.Load());
        Assert.True(File.Exists(_store.BackupFilePath));

        var recovered = new CameraConfigStore(_store.BackupFilePath).Load();
        Assert.Equal(2, recovered.Count);
        Assert.Contains(recovered, p => p.Id == "cam-1");
        Assert.Contains(recovered, p => p.Id == "cam-2");
    }

    [Fact]
    public void First_save_creates_no_backup_because_there_is_nothing_to_preserve()
    {
        _store.Save([Sample()]);

        Assert.False(File.Exists(_store.BackupFilePath));
    }

    [Fact]
    public void Save_leaves_no_temp_file_behind()
    {
        _store.Save([Sample()]);

        Assert.False(File.Exists(_store.FilePath + ".tmp"));
    }

    [Fact]
    public void Save_overwrites_a_previous_file()
    {
        _store.Save([Sample("cam-1"), Sample("cam-2", "10.0.0.7")]);
        _store.Save([Sample("cam-3", "10.0.0.9")]);

        var profile = Assert.Single(_store.Load());
        Assert.Equal("cam-3", profile.Id);
    }

    [Fact]
    public void Load_treats_an_empty_file_as_no_cameras()
    {
        File.WriteAllText(_store.FilePath, "   ");

        Assert.Empty(_store.Load());
    }
}

public sealed class CameraProfileTests
{
    [Theory]
    [InlineData("cam-1")]
    [InlineData("cam_1")]
    [InlineData("Cam1")]
    public void Accepts_safe_ids(string id) => Assert.True(CameraProfile.IsValidId(id));

    [Theory]
    [InlineData("")]
    [InlineData("has space")]
    [InlineData("has:colon")]
    [InlineData("has/slash")]
    [InlineData("emoji-\U0001F600")]
    public void Rejects_unsafe_ids(string id) => Assert.False(CameraProfile.IsValidId(id));

    [Fact]
    public void Generated_ids_are_valid_and_unique()
    {
        var first = CameraProfile.NewId();
        var second = CameraProfile.NewId();

        Assert.True(CameraProfile.IsValidId(first));
        Assert.NotEqual(first, second);
    }

    [Fact]
    public void Validate_reports_the_first_problem_it_finds()
    {
        var profile = new CameraProfile { Id = "cam-1", DisplayName = "  ", Host = "192.168.1.50" };

        Assert.False(profile.IsValid);
        Assert.Contains("name", profile.Validate()!, StringComparison.OrdinalIgnoreCase);
    }
}
