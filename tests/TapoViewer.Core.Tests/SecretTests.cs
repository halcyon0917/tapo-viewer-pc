using TapoViewer.Core.Security;

namespace TapoViewer.Core.Tests;

public sealed class SecretTests
{
    [Fact]
    public void Round_trips_characters()
    {
        using var secret = Secret.FromChars("hunter2");

        Assert.Equal(7, secret.Length);
        Assert.True(secret.Reveal().SequenceEqual("hunter2"));
    }

    [Fact]
    public void Handles_an_empty_value()
    {
        using var secret = Secret.FromChars(ReadOnlySpan<char>.Empty);

        Assert.Equal(0, secret.Length);
        Assert.True(secret.Reveal().IsEmpty);
    }

    [Fact]
    public void Reveal_throws_after_disposal()
    {
        var secret = Secret.FromChars("hunter2");
        secret.Dispose();

        Assert.Throws<ObjectDisposedException>(() => _ = secret.Reveal().Length);
    }

    [Fact]
    public void Disposal_is_idempotent()
    {
        var secret = Secret.FromChars("hunter2");

        secret.Dispose();
        secret.Dispose();
    }
}
