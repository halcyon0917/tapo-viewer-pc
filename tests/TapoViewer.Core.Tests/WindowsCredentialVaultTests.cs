using TapoViewer.Core.Security;

namespace TapoViewer.Core.Tests;

/// <summary>
/// These touch the real Windows Credential Manager, under ids prefixed so they cannot collide
/// with a user's actual cameras. Every test removes what it wrote.
/// </summary>
public sealed class WindowsCredentialVaultTests : IDisposable
{
    private const string TestId = "selftest-0000";

    private readonly WindowsCredentialVault _vault = new();

    public void Dispose() => _vault.Delete(TestId);

    [Fact]
    public void Stores_and_retrieves_a_credential()
    {
        _vault.Store(TestId, "camera_user", "s3cret-p@ss");

        using var retrieved = _vault.Retrieve(TestId);

        Assert.NotNull(retrieved);
        Assert.Equal("camera_user", retrieved.UserName);
        Assert.True(retrieved.Password.Reveal().SequenceEqual("s3cret-p@ss"));
    }

    [Fact]
    public void Overwrites_an_existing_credential()
    {
        _vault.Store(TestId, "camera_user", "first");
        _vault.Store(TestId, "camera_user2", "second");

        using var retrieved = _vault.Retrieve(TestId);

        Assert.NotNull(retrieved);
        Assert.Equal("camera_user2", retrieved.UserName);
        Assert.True(retrieved.Password.Reveal().SequenceEqual("second"));
    }

    [Fact]
    public void Retrieving_an_unknown_camera_returns_null()
    {
        Assert.Null(_vault.Retrieve("selftest-does-not-exist"));
    }

    [Fact]
    public void Delete_reports_whether_anything_was_removed()
    {
        _vault.Store(TestId, "camera_user", "value");

        Assert.True(_vault.Delete(TestId));
        Assert.False(_vault.Delete(TestId));
        Assert.Null(_vault.Retrieve(TestId));
    }

    [Fact]
    public void Preserves_non_ascii_passwords()
    {
        _vault.Store(TestId, "camera_user", "pásswörd-日本語");

        using var retrieved = _vault.Retrieve(TestId);

        Assert.NotNull(retrieved);
        Assert.True(retrieved.Password.Reveal().SequenceEqual("pásswörd-日本語"));
    }

    [Theory]
    [InlineData("has space")]
    [InlineData("has:colon")]
    [InlineData("has/slash")]
    [InlineData("has\\backslash")]
    public void Rejects_camera_ids_that_could_collide_with_other_entries(string cameraId)
    {
        // The target name is a key in a machine-global namespace. Allowing separators would let
        // a crafted id address another application's credentials.
        Assert.Throws<ArgumentException>(() => _vault.Store(cameraId, "u", "p"));
        Assert.Throws<ArgumentException>(() => _vault.Retrieve(cameraId));
        Assert.Throws<ArgumentException>(() => _vault.Delete(cameraId));
    }

    [Fact]
    public void Rejects_a_password_beyond_the_windows_blob_limit()
    {
        var tooLong = new string('x', 1281);
        Assert.Throws<ArgumentException>(() => _vault.Store(TestId, "camera_user", tooLong));
    }
}
